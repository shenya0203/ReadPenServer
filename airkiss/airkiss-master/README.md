# AirKiss

AirKiss是微信硬件平台提供的一种WIFI设备快速入网配置技术，要使用微信客户端的方式配置设备入网，需要设备支持AirKiss技术。

AirKiss主要在如下场景中使用：

- 待接入互联网的设备不具备输入输出能力，如空调、空气净化器、烟雾报警器等。
- 用户不具备通过设备热点的方式进行配置的能力，如老人、家庭主妇等缺乏相关IT知识的用户人群。

AirKiss技术应用实例（以智能插座为例）：

![AirKiss Use Case](http://iot.weixin.qq.com/wiki/static/image/7_1-1.png)

用户使用AirKiss的交互流程如下：

1. 用户按下智能插座上的配置按键，AirKiss指示灯闪烁，智能插座进入信息接收状态。
2. 用户打开微信手机客户端，进入设备的联网配置界面（设备厂商开发的HTML5页面），唤起AirKiss的SSID与密码发送界面，当前无线网络环境下无线路由器的SSID已经默认选中，用户只需要填写密码，然后点击发送即可。

> http://iot.weixin.qq.com/wiki/document-7_1.html

一键配置相关命令（For MT7688 on OpenWrt）

```
iwpriv apcli0 elian start

iwpriv apcli0 elian result

iwpriv apcli0 elian stop
```

查看接收数据的时间

```
date; iwpriv apcli0 elian start; while true; do iwpriv apcli0 elian result; date; done
```
