# toysniffer

    本项目在 macOS 上设计并实现了基于 Qt GUI 的网络嗅探器，使用libpcap库进行抓包，BPF进行协议过滤。

    运行效果如下：

<img src="image/README/1730800852264.png" alt="1730800852264" style="zoom: 50%;" />

按功能划分，项目总体按三个部分来开发：

1. libpcap网络数据包捕获和过滤（capture.h capture.cpp）
2. 网络数据协议解析（parser.h parser.cpp）
3. TCP数据流监控（flowtracker.h flowtracker.cpp）

代码结构如下：

```
├── gui
│   ├── build
│   ├── gui.pro
│   ├── gui.pro.user
│   ├── main.cpp
│   ├── mainwindow.cpp
│   ├── mainwindow.h
│   └── mainwindow.ui
├── include
│   ├── capture.h
│   ├── flowtracker.h
│   └── parser.h
├── src
│   ├── capture.cpp
│   ├── flowtracker.cpp
│   └── paser.cpp
└── README.md
```

## capture

**PacketCapture** 类用于实现网络数据包的捕获，利用 **libpcap** 库提供的功能，能够从指定网络接口实时捕获数据包，并通过回调机制将捕获到的数据包传递给用户进行处理。

**主要结构**

**RawPacket** 结构体: 存储捕获到的原始数据包信息，包括时间戳 (**ts**)、数据包头 (**header**) 和数据 (**data**)。使用智能指针管理内存，以避免内存泄漏。

**PacketCapture**类 **：**

主要功能包括启动和停止数据包捕获，提供回调机制供外部使用。提供以下主要方法：

* startCapture：开始在指定网络接口上捕获数据包，并可选择设置过滤器。
* stopCapture：停止数据包捕获并清理资源。
* callback：用于传递捕获到的数据包的回调函数。

**实现细节**

**捕获初始化** ：

    在**startCapture** 方法中，使用 **pcap_open_live** 打开指定的网络接口进行捕获。若打开失败，输出错误信息并返回 **false**。如果提供了过滤器表达式，使用 **pcap_compile** 编译过滤器，并使用 **pcap_setfilter** 设置过滤器。启动一个新线程进行数据包捕获循环，调用 **captureLoop** 方法。

**数据包捕获** ：

    在**captureLoop** 方法中，使用 **pcap_loop** 函数进入循环捕获数据包，并将每个捕获到的数据包传递给 **packetHandler** 进行处理。

**数据包处理** ：

    packetHandler 方法创建**RawPacket** 对象，复制数据包头和数据，最后调用用户提供的回调函数将数据包传递出去。

## parser

    解析器主要负责解析网络数据包的不同层次和协议，包括以太网、IPv4、IPv6、传输层协议（如TCP、UDP、ICMP、IGMP）和应用层协议（如HTTP、DNS、ARP等）。该实现的目的是为了提供一个全面的网络数据包分析工具，便于用户了解网络通信的细节。

**主要功能**

    **以太网层解析** ：提取以太网帧的源MAC地址、目标MAC地址及EtherType，以决定上层协议。

**	IPv4和IPv6解析** ：分别解析IPv4和IPv6数据包的头部信息，获取源IP和目标IP。对于IPv6，还支持解析扩展头。

**传输层协议解析** ：

    **TCP** ：解析TCP头部信息，检查是否为HTTP请求，并提取相关请求信息（如方法、路径和版本）。

    **UDP** ：解析UDP头部，识别是否包含DNS查询，并提取DNS信息。

    **ICMP** ：解析ICMP数据包头部，提取类型、代码和校验和信息。

    **IGMP** ：解析IGMP数据包头部，提取类型和组地址。

**应用层协议解析** ：

    **HTTP/HTTPS** ：从TCP负载中提取HTTP请求行和请求头，提供详细的HTTP请求信息。

    **DNS** ：提取DNS查询计数、应答计数等信息，提供DNS数据包的基本统计信息。

**	ARP** ：解析ARP请求/应答的相关信息，包括源和目标IP地址及MAC地址。

**解析逻辑**

    解析逻辑遵循自下而上的层次结构。首先解析以太网头部以判断上层协议类型，随后依次解析IP层、传输层和应用层协议。根据协议的不同，解析器调用不同的解析函数，逐层深入获取包内信息。

**以太网层解析**

    **以太网头部解析** ：使用**parseEthernetHeader**函数提取以太网头部信息，并根据EtherType判断后续协议类型。

**IPv4层解析**

    **IPv4头部解析** ：使用**parseIPv4Packet**解析IPv4头部，提取源和目标IP地址。

    **传输层协议判断** ：通过协议首字母（如TCP、UDP、ICMP、IGMP）进一步调用对应的解析函数进行详细解析。

**传输层解析**

    **TCP解析** ：使用**parseTCPPacket**提取TCP头部，检测HTTP流量。

    **UDP解析** ：使用**parseUDPPacket**提取UDP头部，识别DNS流量。

    **ICMP解析** ：使用**parseICMPPacket**提取ICMP头部信息。

    **IGMP解析** ：使用**parseIGMPPacket**提取IGMP头部信息。

**应用层解析**

    **HTTP解析** ：调用**parseHTTP**提取HTTP请求信息，包括请求方法、路径和头部内容。

    **DNS解析** ：调用**parseDNSPacket**提取DNS查询和应答信息。

    **ARP解析** ：调用**parseARPHeader**提取ARP信息，更新PacketInfo结构体。

**数据结构**

    解析器使用**PacketInfo**结构体保存解析后的信息，包括：

    protocol：协议名称

    info：详细信息

    sourceIP**、**destinationIP：源和目标IP地址

    sourcePort**、**destinationPort：源和目标端口

    length：数据包长度

    此外，还使用**ProtocolNode**结构体表示协议节点，包括协议名称、详细信息及子节点。

## flowtracker

    该模块主要负责跟踪网络数据包的流量，并判断特定进程是否参与了该流量。通过结合系统	命令（如**lsof**），模块能够实时监控进程与网络流量之间的关系，以便进行进一步分析。

**主要功能**

    **流量追踪** ：根据数据包的信息（如源IP、目标IP、源端口、目标端口）追踪网络流量。

    **进程关联检查** ：通过执行系统命令，检查指定进程是否与数据包的源IP和端口匹配。

    **数据存储** ：将每个流量的时间戳和长度存储在相应的流量记录中。

**结构与实现**

**数据结构**

    **FlowKey** ：用于唯一标识流量的键，包括源IP、目标IP、源端口和目标端口。重载了**==**运算符以支持哈希表的相等判断。

    **FlowTracker** ：负责流量追踪的主要类，内部使用**std::unordered_map**来存储流量数据。

**关键函数**

    trackPacket：跟踪并记录数据包信息，将时间戳和数据包长度存储到对应的流量记录中。

    getFlows：返回当前跟踪的所有流量信息。

    processTrackPacket：处理数据包，如果数据包来自特定进程，则调用**trackPacket**进行记录。

    executeCommand：执行给定的系统命令并返回输出结果，用于提取进程相关信息。

    **isPacketFromProcess：判断数据包是否来自特定进程。通过解析**lsof**命令的输出，检查IP和端口是否匹配。

**命令执行**

    **executeCommand**函数使用**popen**执行外部命令（如**lsof**），并读取输出。处理后输出结果存储到字符串向量中，以供进一步分析。

**解析逻辑**

    **数据包跟踪** ：当一个数据包到达时，**processTrackPacket**会被调用，首先通过**isPacketFromProcess**检查数据包是否来自指定进程。如果是，则调用**trackPacket**记录流量信息。

    **进程检测** ：在**isPacketFromProcess**中，通过执行**lsof -i -n -P**命令获取当前系统中打开的网络连接，并筛选出与目标进程ID相关的连接。通过解析输出信息，提取IP和端口，检查是否与数据包的源IP和源端口匹配。

    **流量记录** ：在**trackPacket**中，使用**FlowKey**构造唯一标识符，并将数据包的时间戳和长度存储到相应的流量记录中。

## gui

**类定义与成员变量**

    **MainWindow** 继承自 **QMainWindow**，提供了主窗口的功能。**

包含多个私有成员变量，例如**ui**、**timer**、**packetInfoModel**、**capture** 等，分别用于管理界面、定时器、数据模型和数据包捕获。

**构造函数**

    在构造函数中初始化界面、设置窗口标题和大小，创建定时器，设置网络接口和过滤器，配置数据表模型，并连接信号与槽。

使用**pcap_findalldevs** 函数列出所有网络设备，并添加到下拉框中以供选择。

**数据包捕获**

    packetCallback 函数是 libpcap 的回调函数，用于处理捕获到的数据包。它解析数据包，并将相关信息加载到数据模型中，以便在界面上显示。

使用**FlowTracker** 类跟踪与所选进程相关的数据包。

**数据模型与界面更新**

    loadPacketData 函数将捕获到的数据包信息添加到**packetInfoModel** 中，以更新表格视图。

    formatRawData 函数格式化原始数据为十六进制和 ASCII 格式。

**图表与波形**

    代码中设置了一个 QChart 来显示数据包长度的波形图，允许实时可视化数据流。

    updateWaveform 方法会在定时器超时时调用，以更新波形图。

**信号与槽**

    使用 Qt 的信号与槽机制来处理用户输入（例如启动和停止捕获、选择网络接口和过滤器、选择数据包等）。

这段代码实现了一个功能丰富的网络嗅探器主窗口，包括数据包捕获、过滤、可视化和与用户交互的能力。它使用了 Qt 的多种组件，如表格视图、下拉框和图表，来提供直观的用户界面。通过对数据包的实时分析，用户可以监控网络流量并对数据进行深入分析。
