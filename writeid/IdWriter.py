import ipaddress
import socket
import sys
import io
import telnetlib
import logging
import time
import re
from typing import Union
import concurrent.futures
import netifaces
import psutil
import wmi
import datetime
import pythoncom


# 定义日志
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s - Line %(lineno)d",
    level=logging.INFO,
)
# 强制设置 stdout 使用 UTF-8 编码
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
# 扫描指定范围内的IP地址的指定端口


def tel_print(str: bytes):
    content = str.rfind(b"\r\n")
    if content == -1:
        return ""
    else:
        return content


def get_latest_print(tn: telnetlib.Telnet):
    times = 0
    while True:
        time.sleep(0.5)
        content = tn.read_very_eager()
        index1 = content.rfind(b"\r\n")
        index = content.rfind(b"\r\n", 0, index1)
        if index != -1:
            content = content[index + 2 : index1 : 1]
            return content
        else:
            times += 1
            if times >= 7:
                logging.error(f"内容为：{content}")
                return False


# 将 netmask 转换为整数
def netmask_to_int(netmask):
    # 利用 ipaddress 模块将子网掩码转为整数
    return int(ipaddress.IPv4Address(netmask))


def lan_ip_detect():
    gateways = netifaces.gateways()
    gateway = gateways["default"][2][0]
    addresses = []
    # 获取网络接口状态
    stats = psutil.net_if_stats()
    # 获取所有网络接口地址信息
    for interface, addrs in psutil.net_if_addrs().items():
        # 检查接口是否是活动的
        if interface in stats:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    addresses.append(
                        {f"{interface}": addr.address, "netmask": addr.netmask}
                    )
    ipv4 = addresses
    netmast = max(ipv4, key=lambda x: netmask_to_int(x["netmask"]))["netmask"]
    network = list(ipaddress.IPv4Network(f"{gateway}/{netmast}", strict=False).hosts())
    return network


def write_id(tn, id):
    try:
        print(f"开始写入设备ID-{id}")
        tn.write(f"cat /customer/screenId.ini\n".encode("utf-8"))
        time.sleep(0.5)
        tn.write(f'echo "[screen]" > /customer/screenId.ini\n'.encode("utf-8"))
        tn.write(f'echo "deviceId={id}" >> /customer/screenId.ini\n'.encode("utf-8"))
        tn.write(f"sync\n".encode("utf-8"))
        time.sleep(1)
        a = tn.read_very_eager().decode("utf-8", errors="ignore")
        if id in a:
            print(f"写入设备ID成功")
        else:
            print(f"写入设备ID失败")
        tn.close()
        return True
    except Exception as e:
        return False


def generate_temp_device_id(prefix: str = "PSa") -> str:
    """生成时间戳型设备ID，保证在无法获取真实设备指纹时也可写入占位值。"""
    now = datetime.datetime.now()
    return f"{prefix}{now:%Y%m%d%H%M%S}"


def get_uuid() -> str:
    """通过 WMI 获取设备 UUID，失败时回退为网卡 MAC 或时间戳 ID。"""
    fallback_id = generate_temp_device_id()
    initialized = False
    c = None
    try:
        pythoncom.CoInitialize()
        initialized = True
        c = wmi.WMI()

        uuid = ""
        try:
            for system in c.Win32_ComputerSystemProduct():
                if system.UUID:
                    uuid = system.UUID
                    break
        except Exception as err:  # noqa: BLE001
            logging.warning("读取 Win32_ComputerSystemProduct 失败：%s", err)

        if not uuid:
            try:
                for adapter in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    if adapter.MACAddress:
                        uuid = adapter.MACAddress
                        break
            except Exception as err:  # noqa: BLE001
                logging.warning("读取网卡 MAC 地址失败：%s", err)
    except Exception as err:  # noqa: BLE001
        logging.error("初始化 WMI 失败：%s", err)
        return fallback_id
    finally:
        if initialized:
            pythoncom.CoUninitialize()

    if not uuid:
        return fallback_id

    uuid = str(uuid).replace(":", "")[-10:]
    ct = datetime.datetime.now().strftime("%Y")
    return f"PSa{ct}{uuid}"


def scan_port(host, port) -> Union[list, bool, telnetlib.Telnet]:
    try:
        tn = telnetlib.Telnet(host, port, timeout=0.5)
        s = tn.read_until(b"login: ", timeout=0.5)
        index = tel_print(s)
        result = s[index::].decode("utf-8")
        if "login: " in result:
            tn.write(b"root\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(b"ya!2dkwy7-934^\n")
            tn.read_until(
                b"login: can't chdir to home directory '/home/root'", timeout=2
            )
            tn.write(b"cat customer/screenId.ini\n")
            # 循环防止未来得及读取到屏幕id的情况
            max_attempts = 3  # 最大尝试次数
            attempts = 0
            while attempts < max_attempts:
                time.sleep(0.3)
                s = tn.read_very_eager().decode("utf-8")
                pattern = r"deviceId=\s*(\w+)"
                match = re.search(pattern, s)
                if match:
                    screen = match.group(1)
                    break
                else:
                    print(match, host)
                attempts += 1
            else:
                uuid = get_uuid()
                # 如果超过最大尝试次数仍未找到deviceId，关闭连接并返回True
                print(f"\n开始对 {host} 进行写入设备ID-{uuid}")
                write_id(tn, uuid)
                tn.close()
            return False
            return [screen, tn, host]
        else:
            tn.close()

    except Exception:
        return False


def cmd_check(tn: telnetlib.Telnet, cmd: list, text: str):
    times1 = 0
    text = text.encode("utf-8")

    while True:
        for i in cmd:
            tn.write(i.encode("utf-8") + b"\n")
            time.sleep(0.5)
        result = get_latest_print(tn)
        if result:
            if text in result:
                return True
            else:
                if times1 >= 10:
                    return False
                times1 += 1
                continue


addresses = lan_ip_detect()
port = 23
screen_list = []
tn_list = []
host_list = []
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    future = [executor.submit(scan_port, str(ip), port) for ip in addresses]
    completed = 0
    # 等待线程执行完毕
    for f in concurrent.futures.as_completed(future):
        completed += 1
        dengyu = "=" * (int(completed / (len(addresses)) * 100))
        kong = " " * (100 - int(completed / (len(addresses)) * 100))
        total_jindu = f"\r正在检索设备：【{dengyu}{kong}】"
        print(total_jindu, end="", flush=True)
        if f.result():
            screen, tn, host = f.result()
            screen_list.append(screen)
            tn_list.append(tn)
            host_list.append(host)

    if not screen_list:
        input("\n未发现设备，按回车键退出程序")
        sys.exit()

    input("按回车键退出程序...")
    sys.exit()
