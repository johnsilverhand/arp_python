from scapy.all import sendp, Raw
from scapy.all import ARP, sniff
from tkinter import *
from tkinter import ttk
import ctypes
import socket
import struct

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def format_mac(mac_bytes):
    return '-'.join('%02X' % b for b in mac_bytes)

def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', '').replace('-', ''))


class ARPRequest:
    def send_arp_request(self, target_ip, sender_mac):
        try:
            info = ""  # 用来保存报文的相关信息
            # 获取本地主机名和IP地址
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # WLAN2 MAC地址
            #sender_mac = b'\xb4\x8c\x9d\x5c\x82\xd9' 
            #sender_mac = b'\x58\x11\x22\x3b\x40\xdc'#以太网6发送方MAC地址
            
            # 手动构建 ARP 数据包
            # Ethernet 头部信息
            eth_header = struct.pack("!6s6s2s", b'\xff\xff\xff\xff\xff\xff', sender_mac, b'\x08\x06')
            #字节数依次为6 6 2，其中6为目的MAC地址（广播地址），接着为目标MAC地址，然后为协议类型08.06，此处为ARP请求
            # ARP 头部信息
            arp_header = struct.pack("!2s2s1s1s2s6s4s6s4s", b'\x00\x01', 
                                     b'\x08\x00', 
                                     b'\x06', 
                                     b'\x04', 
                                     b'\x00\x01', 
                                     sender_mac, 
                                     socket.inet_aton(local_ip), 
                                     b'\x00\x00\x00\x00\x00\x00', 
                                     socket.inet_aton(target_ip))
            #字节数依次为2 2 1 1 2，其中2个字节为硬件类型00.01以太网硬件，2个字节为协议类型08.00IP地址，1个字节为硬件地址（MAC）长度06，1个字节为协议（IP）地址长度04，2个字节为操作类型00.01，此处为ARP请求
            # #字节数依次为6 4 6 4，其中6个字节为发送方MAC地址，4个字节为发送方IP地址，6个字节为目标MAC地址(请求时为0.0.0.0.0.0)，4个字节为目标IP地址
            packet = eth_header + arp_header
            self.target_ip = target_ip  # 保存目标IP为类属性
            # 使用 scapy 发送数据包
            sendp(Raw(packet))
            
            # 创建一个字符串来保存报文的相关信息
            info = f"本机主机名：{hostname}\n发送方IP: {local_ip}\n发送方MAC: {format_mac(sender_mac)}\n目标IP: {target_ip}\n"
            return True, info
        except Exception as e:
            info = f"发送ARP请求失败！\n原因：{str(e)}"
            return False, info
    def sniff_arp_reply(self, gui_instance):
        def arp_display(packet):
            if packet[ARP].op == 2 and packet[ARP].psrc == self.target_ip:
                gui_instance.update_mac_address(packet[ARP].hwsrc)

        # 使用sniff函数嗅探ARP应答报文
        sniff(prn=arp_display, filter="arp", store=0, count=1)  # count=1表示捕获1个ARP应答报文然后停止嗅探 
class GUI:
    def __init__(self):
        self.root = Tk()
        self.root.title('ARP 请求工具')
        # 添加一个标签提示用户选择MAC地址
        self.mac_label = Label(self.root, text="请选择发送方MAC地址:")
        self.mac_label.pack(pady=10)

        # 创建一个下拉框供用户选择MAC地址
        self.mac_combobox = ttk.Combobox(self.root)
        self.mac_combobox.pack(pady=10)
        self.mac_combobox['values'] = ('b4-8c-9d-5c-82-d9', '58-11-22-3b-40-dc')  
        # 这里列出了预定义的MAC地址,第一个是wlan2的MAC地址，第二个是以太网6的MAC地址
        self.mac_combobox.current(0)  # 设置默认选择的MAC地址，默认为第一个wlan2的MAC地址
        # 提示用户输入目标IP地址
        self.label = Label(self.root, text="请输入目标IP地址:")
        self.label.pack(pady=20)

        self.entry = Entry(self.root)
        self.entry.pack(pady=20)

        self.button = Button(self.root, text="发送ARP请求", command=self.send_arp)
        self.button.pack(pady=20)

        # 添加一个标签显示发送状态
        self.status_label = Label(self.root, text="")
        self.status_label.pack(pady=20)
        # 添加一个Text组件来显示报文的相关信息
        self.info_label = Label(self.root, text="报文信息:")
        self.info_label.pack(pady=10)
        
        self.info_box = Text(self.root, height=10, width=50)
        self.info_box.pack(pady=20)
         # 在其他组件之后添加目标MAC地址文本框
        self.target_mac_entry_label = Label(self.root, text="目标MAC地址:")
        self.target_mac_entry_label.pack(pady=10)

        self.target_mac_entry = Entry(self.root)
        self.target_mac_entry.pack(pady=10)
        
        self.arp = ARPRequest()

        # 启动图形界面主循环
        self.root.mainloop()

    def send_arp(self):
        target_ip = self.entry.get()
        selected_mac_str = self.mac_combobox.get()
        selected_mac_bytes = mac_to_bytes(selected_mac_str)
        success, info = self.arp.send_arp_request(target_ip, selected_mac_bytes)
        # 显示报文的相关信息
        self.info_box.delete(1.0, END)  # 清空Text组件
        self.info_box.insert(INSERT, info)  # 插入新的信息
        
        if success:
            self.status_label.config(text="ARP请求已发送！", fg="green")
            self.arp.sniff_arp_reply(self)  # 启动嗅探来捕获ARP应答
            #self.status_label.config(text=target_ip, fg="green")
        else:
            self.status_label.config(text="ARP请求发送失败！", fg="red")
    def update_mac_address(self, mac):
        # 清空目标MAC地址文本框的内容
        self.target_mac_entry.delete(0, END)
        # 将新的MAC地址插入到文本框中
        self.target_mac_entry.insert(0, mac)
# 检查用户是否以管理员权限运行
if is_admin():
    GUI()  # 实例化并启动图形界面
else:
    print("脚本必须以管理员权限运行!")