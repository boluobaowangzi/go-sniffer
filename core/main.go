package main

import (
  "bufio"
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/tcpassembly"
  "github.com/google/gopacket/tcpassembly/tcpreader"
  "io"
  "log"
  "os"
  "strconv"
  "strings"
  "time"

)

type Redis struct {
  port    int
  version string
  cmd     chan string
  done    chan bool
}

func (red Redis) ResolveStream(net, transport gopacket.Flow, r io.Reader) {

  buf := bufio.NewReader(r)
  var cmd string
  var cmdCount = 0
  for {

    line, _, _ := buf.ReadLine()

    if len(line) == 0 {
      buff := make([]byte, 1)
      _, err := r.Read(buff)
      if err == io.EOF {
        red.done <- true
        return
      }
    }

    //Filtering useless data
    if !strings.HasPrefix(string(line), "*") {
      continue
    }

    //Do not display
    if strings.EqualFold(transport.Src().String(), strconv.Itoa(red.port)) == true {
      continue
    }

    //run
    l := string(line[1])
    cmdCount, _ = strconv.Atoi(l)
    cmd = ""
    for j := 0; j < cmdCount * 2; j++ {
      c, _, _ := buf.ReadLine()
      if j & 1 == 0 {
        continue
      }
      cmd += " " + string(c)
    }
    fmt.Println(cmd)
  }
}

/**
SetOption
*/
func (red *Redis) SetFlag(flg []string)  {
  c := len(flg)
  if c == 0 {
    return
  }
  if c >> 1 != 1 {
    panic("ERR : Redis num of params")
  }
  for i:=0;i<c;i=i+2 {
    key := flg[i]
    val := flg[i+1]

    switch key {
    case "-p":
      port, err := strconv.Atoi(val);
      red.port = port //之前是redis
      if err != nil {
        panic("ERR : Port error")
      }
      if port < 0 || port > 65535 {
        panic("ERR : Port(0-65535)")
      }
      break
    default:
      panic("ERR : redis's params")
    }
  }
}

/**
BPFFilter
*/
func (red *Redis) BPFFilter() string {
  return "tcp and port "+strconv.Itoa(6379)
}

/**
Version
*/
func (red *Redis) Version() string {
  return red.version
}



//=========================

type Cmd struct {
  Device string
  plugHandle *Redis  //cmd将页面接受的命令形成具体的实例（具体的实例有各自实现的方法）
}

func NewCmd(p *Redis) *Cmd {

  return &Cmd{
    plugHandle:p,
  }
}

//start
func (cm *Cmd) Run() {

  //print help
  if len(os.Args) <= 1 {
    log.Println("之前是打印帮助信息")
    os.Exit(1)
  }

  //parse command
  firstArg := string(os.Args[1])
  if strings.HasPrefix(firstArg, "--") {
    log.Println("之前此处是识别为内部命令")
  } else {
    cm.parsePlugCmd()
  }
}

//Parameters needed for plug-ins
func (cm *Cmd) parsePlugCmd()  {

  if len(os.Args) < 3 {
    fmt.Println("not found [Plug-in name]")
    fmt.Println("go-sniffer [device] [plug] [plug's params(optional)]")
    os.Exit(1)
  }

  //接受命令端的信息
  cm.Device  = os.Args[1]
  plugName  := os.Args[2]
  plugParams:= os.Args[3:]
  log.Println("cm.Device  = os.Args[1]", os.Args[1])
  log.Println("plugName", plugName)
  log.Println("plugParams", plugParams)
  //cm.plugHandle.SetOption(plugName, plugParams) 这个地方就是用来获取实例的具体方法名的
}

//===========================


type Dispatch struct {
  device string
  payload []byte
  Plug *Redis
}

func NewDispatch(red *Redis, cmd *Cmd) *Dispatch {
  return &Dispatch {
    Plug: red,
    device:cmd.Device,
  }
}

func (d *Dispatch) Capture() {

  //init device
  handle, err := pcap.OpenLive(d.device, 65535, false, pcap.BlockForever) //这个是什么意思呢
  if err != nil {
    log.Fatal(err)
    return
  }

  //set filter
  fmt.Println(d.Plug.BPFFilter())
  err = handle.SetBPFFilter(d.Plug.BPFFilter())
  if err != nil {
    log.Fatal(err)
  }

  //capture
  src     := gopacket.NewPacketSource(handle, handle.LinkType())
  packets := src.Packets()

  //set up assembly
  streamFactory := &ProtocolStreamFactory{
    dispatch:d,
  }
  streamPool := NewStreamPool(streamFactory)
  assembler  := NewAssembler(streamPool)
  ticker     := time.Tick(time.Minute)

  //loop until ctrl+z
  for {
    select {
    case packet := <-packets:
      if packet.NetworkLayer() == nil ||
        packet.TransportLayer() == nil ||
        packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
        fmt.Println("ERR : Unknown Packet -_-")
        continue
      }
      tcp := packet.TransportLayer().(*layers.TCP)
      assembler.AssembleWithTimestamp(
        packet.NetworkLayer().NetworkFlow(),
        tcp, packet.Metadata().Timestamp,
      )
    case <-ticker:
      assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
    }
  }
}

type ProtocolStreamFactory struct {
  dispatch *Dispatch
}

type ProtocolStream struct {
  net, transport gopacket.Flow
  r              tcpreader.ReaderStream
}

func (m *ProtocolStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {

  //init stream struct
  stm := &ProtocolStream {
    net:       net,
    transport: transport,
    r:         tcpreader.NewReaderStream(),
  }

  //new stream
  fmt.Println("# Start new stream:", net, transport)

  //decode packet
  go m.dispatch.Plug.ResolveStream(net, transport, &(stm.r))

  return &(stm.r)
}

//==========================
func main() {

  //新建redis变量
  var re = &Redis{
    port:    6379,
    version: "0.1",
  }
  log.Println(re)

  cmd := NewCmd(re)
  cmd.Run()

  log.Println("cmd.device",cmd.Device)
  NewDispatch(re, cmd).Capture()

}
