# SDN
SDN：一个基于SDN的网络管理系统
这个Python程序为某个项目提供了一个重要的功能。该程序使用 Python 3.x 版本，并且需要安装一些第三方库（见下面的 依赖关系）。它包含两个主要函数：add_flow_rule和remove_flow_rule，用于在OpenDaylight SDN网络中添加和删除流表规则。

安装说明
该程序无需安装，只需确保已经安装了Python 3.x版本，并且安装了所需的依赖库（见下面的 依赖关系）。

使用说明
该程序由命令行使用，调用add_flow_rule和remove_flow_rule函数来与网络控制器进行交互。请使用以下命令启动程序：

python main.py

作者
Your Name koalayufei@163.com
如果您有任何问题或建议，请随时联系我们。

介绍
我们使用Mininet创建一个由4个交换机、8个主机和10个子网组成的网络拓扑。我们将h1到h4连接到s1交换机，将h5到h8连接到s2交换机，将h9到h12连接到s3交换机，将h13到h16连接到s4交换机。然后我们将s1和s2、s1和s3、s2和s4、s3和s4连接起来形成一个环状拓扑结构。每个子网都有自己的IP地址段，并且相互之间隔离，以模拟一个真实的企业网络环境。
Network
该文件定义了dijkstra()函数和find_path()函数，用于计算最短路径和查找主机之间的最短路径。它还包含一个示例拓扑图，其中有四个交换机和16个主机。这里我们使用Dijkstra算法作为多路径路由算法，并考虑所有四个交换机之间的连接。
Sdc
该文件包含了add_flow_rule()函数和remove_flow_rule()函数，用于向交换机添加或删除流表规则。这些函数使用REST API与SDN控制器进行交互。您只需要指定交换机的名称、匹配条件和操作，这些函数就会自动构建JSON数据并将其发送到SDN控制器。如果请求失败，则函数会输出错误消息。
请注意，您需要在安装并配置好Mininet和SDN控制器（如OpenDaylight）之后才能成功运行此代码。
在这个示例中，我们使用了scapy模块来监听网络流量。listen_network()函数会不停地监听网络流量，当有数据包到达时，它就根据协议类型调用相应的处理函数（例如handle_arp()、handle_icmp()等）。处理函数中会根据源IP地址和目标IP地址查找最短路径，并向途中的每个交换机添加相应的流表规则。这些函数还会在控制台上输出一些调试信息，以便我们可以了解程序的运行情况。
主程序入口点启动了Mininet拓扑，配置了SDN交换机，并启动了一个线程来监听网络流量。它还使用一个无限循环来等待用户输入，当用户输入q时，程序会退出并停止Mininet拓扑。
