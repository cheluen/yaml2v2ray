# YAML转V2rayN节点工具[自用]

## 功能介绍

这是一个将Clash配置文件（YAML格式）中的节点转换为V2rayN可用格式的工具。支持以下协议类型的转换：

- VMess
- Shadowsocks (SS)
- Trojan
- VLESS
- Hysteria2 (hy2)

每种协议支持各种传输方式（TCP、WebSocket、gRPC等）和TLS配置。

## 使用方法

1. 将Clash配置文件（.yaml或.yml格式）放在与程序相同的目录下
2. 运行程序：
   ```
   python main.py
   ```
3. 程序会自动处理目录下所有YAML文件，并将转换后的节点保存到`v2ray.txt`文件中

## 依赖安装

```
pip install -r requirements.txt
```

## 注意事项

- 转换后的节点格式符合V2rayN的链接格式要求
- 每个节点占一行
- 如果转换过程中出现错误，程序会输出相应的错误信息，但会继续处理其他节点
- 支持批量处理多个YAML文件
