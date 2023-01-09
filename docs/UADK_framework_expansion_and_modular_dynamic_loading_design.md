## UADK framework expansion and modular dynamic loading design

author：Liu Longfang	Date：2022/10/20
### **UADK Existing Framework：**
​		In the current UADK user-mode framework that supports SVA features, UACCE is still relied on to obtain a unified accelerator device control interface, but it is no longer strongly coupled with hardware devices like warpdrive, and is also divided into three layers internally: the algorithm interface layer, The framework interface layer and the user-mode driver layer are divided by the algorithm library, control plane, and data plane seen by the user. The entire framework structure is as follows：

<svg xmlns:ev="http://www.w3.org/2001/xml-events" width="1000" xmlns:xlink="http://www.w3.org/1999/xlink" height="500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2000 1000"><style type="text/css"><![CDATA[
.st1 {fill:#000000;font-family:=E5=AE=8B=E4=BD=93;font-size:18pt}
.st2 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:14pt}
.st3 {fill:#1f6391;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
]]></style><defs/><g transform="translate(5,5)" id="page1"><rect x="0" stroke="#808080" fill="#ffffff" width="2245" height="1587" y="0"/><g transform="translate(314.43,148.27)"><path d="M178.5,68.3L178.5,0L0,0L0,68.3L178.5,68.3z" stroke="#3498db" fill="#00b0f0" id="shape1"/><text class="st1"><tspan x="47.2" y="43.6">ALG API</tspan></text></g><g transform="translate(312.43,386.07)"><path d="M180.5,64.9L180.5,0L0,0L0,64.9L180.5,64.9z" stroke="#3498db" fill="#92d050" id="shape2"/><text class="st1"><tspan x="54.2" y="41.9">WD API</tspan></text></g><g transform="translate(512.01,648.27)"><path d="M362.1,55.9L362.1,0L0,0L0,55.9L362.1,55.9z" stroke="#3498db" fill="#ee7c31" id="shape3"/><text class="st1"><tspan x="151.1" y="37.4">UACCE</tspan></text></g><path d="M0,0L532.9,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,495.6,606.4)" stroke-width="2" id="shape4"/><g transform="translate(590.39,399.5)"><path d="M316.5,38L316.5,0L0,0L0,38L316.5,38z" stroke="#3498db" fill="#92d050" id="shape5"/><text class="st1"><tspan x="128.3" y="28.5">libwd</tspan></text></g><g transform="translate(512.01,817.23)"><path d="M586.9,54.1L586.9,0L0,0L0,54.1L586.9,54.1z" stroke="#3498db" fill="#00b0f0" id="shape6"/><text class="st1"><tspan x="221.4" y="36.6">Hisi acc dev</tspan></text></g><g transform="translate(512.02,741.68)"><path d="M499.7,38L499.7,0L0,0L0,38L499.7,38z" stroke="#3498db" fill="#7eccb6" id="shape7"/><text class="st1"><tspan x="148.4" y="28.5">Hisi acc k-driver</tspan></text></g><g transform="translate(1277.56,550.32)"><path d="M209.7,38L209.7,0L0,0L0,38L209.7,38z" stroke="#3498db" fill="#00b0f0" id="shape8"/><text class="st1"><tspan x="9.3" y="28.5">Hisi acc udriver</tspan></text></g><path d="M0,0L1099,0" stroke="#236ea1" fill="none" transform="translate(446.89,629.18)" stroke-width="2" id="shape9"/><g transform="translate(590.39,163.4)"><path d="M316.5,38L316.5,0L0,0L0,38L316.5,38z" stroke="#3498db" fill="#92d050" id="shape10"/><text class="st1"><tspan x="20.3" y="28.5">libwd_crypto/libwd_comp</tspan></text></g><g transform="translate(1382.4,588.32)" id="shape11"><path d="M0,13.9L0,256L-269.6,256" stroke="#236ea1" fill="none" stroke-width="5.33333"/><path stroke-linecap="round" d="M-6.9,13.9L0,0L6.9,13.9L-6.9,13.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M-269.6,262.9L-283.5,256L-269.6,249.1L-269.6,262.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(611.92,507.32)"><path d="M273.5,42.8L273.5,0L0,0L0,42.8L273.5,42.8z" stroke="#3498db" fill="#00b050" id="shape12"/><text class="st1"><tspan x="83.2" y="30.9">scheduler</tspan></text></g><g transform="translate(1288.83,153.9)"><path d="M187.7,57L187.7,0L0,0L0,57L187.7,57z" stroke="#3498db" fill="#7eccb6" id="shape13"/><text class="st1"><tspan x="10.3" y="38">xxx driver ops</tspan></text></g><g transform="translate(1382.68,210.9)" id="shape14"><path d="M0,0L0,307.4L-0.2,335" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0.3,339.4L2.8,334.3C1.9,334.8,.9,335,-0.2,335C-1.3,335,-2.4,334.7,-3.2,334.2L-0.3,339.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(906.91,182.4)" id="shape15"><path d="M0,0L377.5,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M381.9,0L376.7,-3C377.2,-2.1,377.5,-1.1,377.5,0C377.5,1.1,377.2,2.1,376.7,3L381.9,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(748.65,399.5)" id="shape16"><path d="M0,0L0,-193.7" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M0,-198.1L-3,-192.9C-2.1,-193.4,-1.1,-193.7,0,-193.7C1.1,-193.7,2.1,-193.4,3,-192.9L0,-198.1" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(597.17,438.38)" id="shape17"><path d="M0,0L1,201.8" stroke="#236ea1" fill="none" stroke-width="2.66667"/><path stroke-linecap="round" d="M1,209L5.9,200.5C4.4,201.3,2.8,201.8,1,201.8C-0.8,201.8,-2.5,201.4,-3.9,200.5L1,209" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(365.17,711.68)" id="shape18"><text class="st2"><tspan x="9" y="13">Kernel</tspan><tspan x="11" y="38">space</tspan></text></g><g transform="translate(365.17,282.3)" id="shape19"><text class="st2"><tspan x="17" y="13">User</tspan><tspan x="11" y="38">space</tspan></text></g><path d="M0,0L532.9,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,1546.8,596.4)" stroke-width="2" id="shape20"/><g transform="translate(1573.47,489.8)"><path d="M169.5,60.3L169.5,0L0,0L0,60.3L169.5,60.3z" stroke="#3498db" fill="#92d050" id="shape21"/><text class="st1"><tspan x="25.3" y="39.6">libxxx_drv</tspan></text></g><g transform="translate(76.93,399.5)" id="shape22"><text class="st2"><tspan x="26.3" y="25.5">control cmd</tspan></text></g><path d="M4.4,64.6L4.4,9L0,9L8.9,0L17.7,9L13.3,9L13.3,64.6L4.4,64.6z" stroke="#dd7195" fill="#dd7195" transform="matrix(0,1,-1,0,284.8,413.2)" id="shape23"/><g transform="translate(76.93,163.4)" id="shape24"><text class="st2"><tspan x="27.3" y="25.5">data stream</tspan></text></g><path d="M13.2,5.5L62.8,5.5L62.8,0L76,11L62.8,22L62.8,16.5L13.2,16.5L13.2,22L0,11L13.2,0L13.2,5.5z" stroke="#2da2bf" fill="#2da2bf" transform="translate(214.47,171.4)" id="shape25"/><g transform="translate(406.43,49.68)" id="shape26"><text class="st2"><tspan x="10.3" y="25.5">symble visibility</tspan></text></g><g transform="translate(748.65,507.32)" id="shape27"><path d="M0,0L0,-65.4" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,-69.8L-3,-64.6C-2.1,-65.1,-1.1,-65.4,0,-65.4C1.1,-65.4,2.1,-65.1,3,-64.6L0,-69.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(748.31,647.38)" id="shape28"><path d="M0,-6L.3,-97.3" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M3,-6L0,0L-3,-6L3,-6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><path d="M0,0L532.8,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,1250.4,603.1)" stroke-width="2" id="shape29"/><g transform="translate(864.44,61.68)" id="shape30"><text class="st2"><tspan x="42.3" y="25.5">API level</tspan></text></g><g transform="translate(1296.89,61.68)" id="shape31"><text class="st2"><tspan x="32.3" y="25.5">User driver</tspan></text></g><g transform="translate(693.09,704.12)" id="shape32"><path d="M0,0L-0,31.9" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0,36.3L3,31.1C2.1,31.6,1.1,31.9,-0,31.9C-1.1,31.9,-2.1,31.6,-3,31.1L-0,36.3" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(761.89,779.68)" id="shape33"><path d="M0,0L0,31.7" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,36.1L3,30.9C2.1,31.4,1.1,31.7,0,31.7C-1.1,31.7,-2.1,31.4,-3,30.9L0,36.1" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(913.31,193.38)" id="shape34"><path d="M0,0L384.8,350" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M388,353L386.2,347.3C386,348.3,385.5,349.2,384.8,350C384,350.9,383.1,351.4,382.1,351.7L388,353" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1052.16,310.83)" id="shape35"><text class="st2"><tspan x="31.4" y="25.5">dlopen</tspan></text></g><path d="M25.2,10.5L58.5,10.5L58.5,0L83.7,21L58.5,41.9L58.5,31.5L25.2,31.5L25.2,41.9L0,21L25.2,0L25.2,10.5z" stroke="#2da2bf" fill="#0070c0" transform="translate(499.79,161.29)" id="shape36"/><path d="M25.2,10.5L58.5,10.5L58.5,0L83.7,21L58.5,41.9L58.5,31.5L25.2,31.5L25.2,41.9L0,21L25.2,0L25.2,10.5z" stroke="#2da2bf" fill="#0070c0" transform="translate(499.79,399.36)" id="shape37"/><g transform="translate(1573.47,409.79)" id="shape38"><text class="st3"><tspan x="4.4" y="18.4">Each udriver compilation </tspan><tspan x="4.4" y="39.4">generates a separate </tspan><tspan x="4.4" y="60.4">library file</tspan></text></g></g></svg>


​    The external interface has two parts, the framework interface part and the algorithm interface part. The framework interface part is mainly the external control interface of libwd, which mainly deals with the processing of process-level resources, the operation of hardware devices, the queue allocation operation, and the initialization of the matching scheduler.

​    The second part is the interface related to the algorithm, which is mainly the data layer interface for performing task services. Since we mainly support two types of algorithms, encryption and compression, all algorithm interfaces are compiled into two libraries, crypto library and comp library.

​    In addition to the external interface, the rest is the user-mode driver layer, which is strongly related to the operation of the device. The corresponding algorithm operation interface will have a southbound interface to connect to the user-mode driver, and the task data will be sent to the user-mode driver through these internal interfaces. and then sent by the device driver to the hardware device for processing.

There is no major problem with the whole framework, and the algorithm function and operating efficiency are relatively good, but the small problem is that it is too deeply coupled with Kunpeng's accelerator:

1.  The control layer interface is fully functional, and there are a large number of device operation interfaces for Kunpeng acceleration devices.

2. The connection between the API layer and the user-mode driver layer is realized through static coding. Although it is layered through the compiled library, in fact it can only call the interface of the Kunpeng accelerator user-mode driver, and the name of the driver's ops is different depending on the type of algorithm. There is no unification. For other instruction acceleration modes, by installing the corresponding driver, even if the driver is implemented according to the standard driver_ops, it still cannot be linked and used.


### **UADK New Framework Design：**
​    The new framework is just an extension of the original framework. The basic layering remains unchanged. It is still three parts. It just optimizes the device driver adaptation method, and adds support for software computing, instruction acceleration, and third-party acceleration devices. and unified the southbound interface for user-mode drivers:

<svg xmlns:ev="http://www.w3.org/2001/xml-events" width="1000" xmlns:xlink="http://www.w3.org/1999/xlink" height="500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2000 1000"><style type="text/css"><![CDATA[
.st1 {fill:#000000;font-family:=E5=AE=8B=E4=BD=93;font-size:18pt}
.st2 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:14pt}
.st3 {fill:#1f6391;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
]]></style><defs/><g transform="translate(5,5)" id="page1"><rect x="0" stroke="#808080" fill="#ffffff" width="2245" height="1587" y="0"/><g transform="translate(243.69,124.59)"><path d="M160.1,68.3L160.1,0L0,0L0,68.3L160.1,68.3z" stroke="#3498db" fill="#00b0f0" id="shape1"/><text class="st1"><tspan x="38.1" y="43.6">ALG API</tspan></text></g><g transform="translate(243.69,362.39)"><path d="M160.1,64.9L160.1,0L0,0L0,64.9L160.1,64.9z" stroke="#3498db" fill="#92d050" id="shape2"/><text class="st1"><tspan x="44.1" y="41.9">WD API</tspan></text></g><g transform="translate(422.92,624.59)"><path d="M362.1,55.9L362.1,0L0,0L0,55.9L362.1,55.9z" stroke="#3498db" fill="#ee7c31" id="shape3"/><text class="st1"><tspan x="151.1" y="37.4">UACCE</tspan></text></g><path d="M0,0L532.9,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,406.6,582.7)" stroke-width="2" id="shape4"/><g transform="translate(501.29,375.82)"><path d="M316.5,38L316.5,0L0,0L0,38L316.5,38z" stroke="#3498db" fill="#92d050" id="shape5"/><text class="st1"><tspan x="128.3" y="28.5">libwd</tspan></text></g><g transform="translate(1282.88,793.56)"><path d="M221.9,54.1L221.9,0L0,0L0,54.1L221.9,54.1z" stroke="#3498db" fill="#ffc000" id="shape6"/><text class="st1"><tspan x="27.4" y="36.6">others acc dev</tspan></text></g><g transform="translate(1270.97,718)"><path d="M245.7,38L245.7,0L0,0L0,38L245.7,38z" stroke="#3498db" fill="#7eccb6" id="shape7"/><text class="st1"><tspan x="9.3" y="28.5">others acc k-driver</tspan></text></g><g transform="translate(1144.87,494.79)"><path d="M213.9,38L213.9,0L0,0L0,38L213.9,38z" stroke="#3498db" fill="#00b0f0" id="shape8"/><text class="st1"><tspan x="11.5" y="28.5">Hisi acc udriver</tspan></text></g><path d="M0,0L1651.7,0" stroke="#236ea1" fill="none" transform="translate(357.79,605.5)" stroke-width="2" id="shape9"/><g transform="translate(501.29,139.72)"><path d="M316.5,38L316.5,0L0,0L0,38L316.5,38z" stroke="#3498db" fill="#92d050" id="shape10"/><text class="st1"><tspan x="20.3" y="28.5">libwd_crypto/libwd_comp</tspan></text></g><g transform="translate(958.38,394.82)" id="shape11"><path d="M0,0L-136.2,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-140.6,0L-135.4,3C-135.9,2.1,-136.2,1.1,-136.2,0C-136.2,-1.1,-135.9,-2.1,-135.4,-3L-140.6,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(522.83,483.64)"><path d="M273.5,42.8L273.5,0L0,0L0,42.8L273.5,42.8z" stroke="#3498db" fill="#00b050" id="shape12"/><text class="st1"><tspan x="83.2" y="30.9">scheduler</tspan></text></g><g transform="translate(1251.82,191.72)" id="shape13"><path d="M0,0L0,298.7" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,303.1L3,297.9C2.1,298.4,1.1,298.7,0,298.7C-1.1,298.7,-2.1,298.4,-3,297.9L0,303.1" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(817.81,158.72)" id="shape14"><path d="M0,0L344.3,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M348.7,0L343.5,-3C344,-2.1,344.3,-1.1,344.3,0C344.3,1.1,344,2.1,343.5,3L348.7,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1032.84,361.82)" id="shape15"><path d="M0,0L0,-184.6L145.3,-184.6" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M149.7,-184.6L144.5,-187.6C145,-186.7,145.3,-185.7,145.3,-184.6C145.3,-183.5,145,-182.5,144.5,-181.6L149.7,-184.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(659.55,375.82)" id="shape16"><path d="M0,0L0,-193.7" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M0,-198.1L-3,-192.9C-2.1,-193.4,-1.1,-193.7,0,-193.7C1.1,-193.7,2.1,-193.4,3,-192.9L0,-198.1" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1605.29,379.29)"><path d="M197.2,38L197.2,0L0,0L0,38L197.2,38z" stroke="#3498db" fill="#92d050" id="shape17"/><text class="st1"><tspan x="15.1" y="28.5">CPU CE udriver</tspan></text></g><g transform="translate(1754.72,328.29)"><path d="M214.8,38L214.8,0L0,0L0,38L214.8,38z" stroke="#3498db" fill="#92d050" id="shape18"/><text class="st1"><tspan x="17.4" y="28.5">CPU SVE udriver</tspan></text></g><g transform="translate(1337.15,158.72)" id="shape19"><path d="M0,0L366.8,0L366.8,216.2" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M366.8,220.6L369.8,215.4C368.9,215.9,367.9,216.2,366.8,216.2C365.7,216.2,364.6,215.9,363.8,215.4L366.8,220.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1337.15,158.72)" id="shape20"><path d="M0,0L525,0L525,165.2" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M525,169.6L528,164.4C527.1,164.9,526.1,165.2,525,165.2C523.9,165.2,522.9,164.9,522,164.4L525,169.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(508.07,414.7)" id="shape21"><path d="M0,0L1,200.2" stroke="#236ea1" fill="none" stroke-width="4"/><path stroke-linecap="round" d="M1,209L7,198.6C5.2,199.6,3.1,200.2,1,200.2C-1.2,200.2,-3.3,199.7,-5,198.6L1,209" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(276.07,688)" id="shape22"><text class="st2"><tspan x="9" y="13">Kernel</tspan><tspan x="11" y="38">space</tspan></text></g><g transform="translate(276.07,258.62)" id="shape23"><text class="st2"><tspan x="17" y="13">User</tspan><tspan x="11" y="38">space</tspan></text></g><path d="M0,0L551.6,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,2005,595.4)" stroke-width="2" id="shape24"/><g transform="translate(2015.19,472.49)"><path d="M140.4,60.3L140.4,0L0,0L0,60.3L140.4,60.3z" stroke="#3498db" fill="#92d050" id="shape25"/><text class="st1"><tspan x="10.2" y="39.6">libxxx_drv</tspan></text></g><g transform="translate(25.53,375.82)" id="shape26"><text class="st2"><tspan x="26.3" y="25.5">control cmd</tspan></text></g><path d="M4.4,64.6L4.4,9L0,9L8.9,0L17.7,9L13.3,9L13.3,64.6L4.4,64.6z" stroke="#dd7195" fill="#dd7195" transform="matrix(0,1,-1,0,233.4,389.6)" id="shape27"/><g transform="translate(25.53,139.72)" id="shape28"><text class="st2"><tspan x="27.3" y="25.5">data stream</tspan></text></g><path d="M13.2,5.5L62.8,5.5L62.8,0L76,11L62.8,22L62.8,16.5L13.2,16.5L13.2,22L0,11L13.2,0L13.2,5.5z" stroke="#2da2bf" fill="#2da2bf" transform="translate(163.07,147.72)" id="shape29"/><g transform="translate(317.34,26)" id="shape30"><text class="st2"><tspan x="10.3" y="25.5">symble visibility</tspan></text></g><g transform="translate(902.92,488.43)" id="shape31"><text class="st2"><tspan x="19.4" y="13">dlopen()-></tspan><tspan x="16.4" y="38">register alg</tspan></text></g><g transform="translate(1662.55,535.32)"><path d="M327.6,54.1L327.6,0L0,0L0,54.1L327.6,54.1z" stroke="#3498db" fill="#00b0f0" id="shape32"/><text class="st1"><tspan x="116.3" y="36.6">CPU core</tspan></text></g><g transform="translate(1703.9,417.29)" id="shape33"><path d="M0,13.9L0,100.2" stroke="#236ea1" fill="none" stroke-width="5.33333"/><path stroke-linecap="round" d="M-6.9,13.9L0,0L6.9,13.9L-6.9,13.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M6.9,100.2L0,114.1L-6.9,100.2L6.9,100.2" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1862.11,366.29)" id="shape34"><path d="M0,13.9L0,152.7" stroke="#236ea1" fill="none" stroke-width="5.33333"/><path stroke-linecap="round" d="M-6.9,13.9L0,0L6.9,13.9L-6.9,13.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M6.9,152.7L0,166.5L-6.9,152.7L6.9,152.7" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(659.55,483.64)" id="shape35"><path d="M0,0L0,-65.4" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,-69.8L-3,-64.6C-2.1,-65.1,-1.1,-65.4,0,-65.4C1.1,-65.4,2.1,-65.1,3,-64.6L0,-69.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(659.07,620.66)" id="shape36"><path d="M0,-6L.5,-94.2" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M3,-6L0,0L-3,-6L3,-6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><path d="M0,0L553.3,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,1143,601.6)" stroke-width="2" id="shape37"/><g transform="translate(775.34,38)" id="shape38"><text class="st2"><tspan x="42.3" y="25.5">API level</tspan></text></g><g transform="translate(1417.64,38)" id="shape39"><text class="st2"><tspan x="32.3" y="25.5">User driver</tspan></text></g><g transform="translate(558.87,682.43)" id="shape40"><path d="M0,0L0,31.2" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,35.6L3,30.4C2.1,30.9,1.1,31.2,0,31.2C-1.1,31.2,-2.1,30.9,-3,30.4L0,35.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1393.82,756)" id="shape41"><path d="M0,0L-0,33.2" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0,37.6L3,32.4C2.1,32.9,1.1,33.2,-0,33.2C-1.1,33.2,-2.1,32.9,-3,32.4L-0,37.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(785.07,652.52)" id="shape42"><path d="M0,0L608.7,0L608.7,61.1" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M608.7,65.5L611.7,60.3C610.9,60.8,609.8,61.1,608.7,61.1C607.7,61.1,606.6,60.8,605.7,60.3L608.7,65.5" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1421.04,450.12)"><path d="M232.2,38L232.2,0L0,0L0,38L232.2,38z" stroke="#3498db" fill="#ffc000" id="shape43"/><text class="st1"><tspan x="8.1" y="28.5">others acc udriver</tspan></text></g><g transform="translate(1537.13,488.12)" id="shape44"><path d="M0,13.9L0,332.5L-18.5,332.5" stroke="#236ea1" fill="none" stroke-width="5.33333"/><path stroke-linecap="round" d="M-6.9,13.9L0,0L6.9,13.9L-6.9,13.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M-18.5,339.4L-32.4,332.5L-18.5,325.6L-18.5,339.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1337.15,158.72)" id="shape45"><path d="M0,0L200,0L200,287" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M200,291.4L203,286.2C202.1,286.7,201.1,287,200,287C198.9,287,197.9,286.7,197,286.2L200,291.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(422.92,793.56)"><path d="M586.9,54.1L586.9,0L0,0L0,54.1L586.9,54.1z" stroke="#3498db" fill="#00b0f0" id="shape46"/><text class="st1"><tspan x="221.4" y="36.6">Hisi acc dev</tspan></text></g><g transform="translate(422.92,718)"><path d="M499.7,38L499.7,0L0,0L0,38L499.7,38z" stroke="#3498db" fill="#7eccb6" id="shape47"/><text class="st1"><tspan x="148.4" y="28.5">Hisi acc k-driver</tspan></text></g><g transform="translate(672.79,756)" id="shape48"><path d="M0,0L0,31.7" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,36.1L3,30.9C2.1,31.4,1.1,31.7,0,31.7C-1.1,31.7,-2.1,31.4,-3,30.9L0,36.1" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><path d="M25.2,10.5L58.5,10.5L58.5,0L83.7,21L58.5,41.9L58.5,31.5L25.2,31.5L25.2,41.9L0,21L25.2,0L25.2,10.5z" stroke="#2da2bf" fill="#0070c0" transform="translate(410.7,137.75)" id="shape49"/><path d="M25.2,10.5L58.5,10.5L58.5,0L83.7,21L58.5,41.9L58.5,31.5L25.2,31.5L25.2,41.9L0,21L25.2,0L25.2,10.5z" stroke="#2da2bf" fill="#0070c0" transform="translate(410.7,375.82)" id="shape50"/><g transform="translate(2015.19,382.16)" id="shape51"><text class="st3"><tspan x="4.4" y="18.4">Each udriver compilation </tspan><tspan x="4.4" y="39.4">generates a separate </tspan><tspan x="4.4" y="60.4">library file</tspan></text></g><g transform="translate(958.38,361.82)" id="shape52"><path d="M0,33C-0,14.8,33.3,-0,74.5,-0C115.6,-0,148.9,14.8,148.9,33C148.9,51.2,115.6,66,74.5,66C33.3,66,0,51.2,0,33z" stroke="#3498db" fill="#00b050"/><text class="st1"><tspan x="26.5" y="42.5">alg list</tspan></text></g><g transform="translate(1166.5,125.72)" id="shape53"><path d="M0,33C-0,14.8,38.2,0,85.3,0C132.4,0,170.6,14.8,170.6,33C170.6,51.2,132.4,66,85.3,66C38.2,66,0,51.2,0,33z" stroke="#3498db" fill="#7eccb6"/><text class="st1"><tspan x="25.3" y="42.5">driver ops</tspan></text></g><g transform="translate(1251.82,532.79)" id="shape54"><path d="M0,13.9L0,287.8L-228.2,287.8" stroke="#236ea1" fill="none" stroke-width="5.33333"/><path stroke-linecap="round" d="M-6.9,13.9L0,0L6.9,13.9L-6.9,13.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M-228.2,294.8L-242,287.8L-228.2,280.9L-228.2,294.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1144.87,513.79)" id="shape55"><path d="M0,0L-112,0L-112,-81.6" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M-112,-86L-115,-80.8C-114.1,-81.3,-113.1,-81.6,-112,-81.6C-110.9,-81.6,-109.9,-81.3,-109,-80.8L-112,-86" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g></g></svg>


​    The interface of the control layer still exists, and the internal optimization abstraction is carried out. The interface specific to a certain device operation is no longer added, but the original supported interface is still preserved to ensure compatibility, and only the optimized interface is added.

​    The original business data layer interface remains unchanged, and the supported algorithms remain unchanged to ensure that the task execution operation does not change and ensure compatibility. By adding the initialization init2 interface, it is convenient for users to use, reduces the process of initialization operations, and reduces the complexity of use.

​    Optimize the API layer and user mode driver layer through the following data structure, and add a new algorithm support list component:

```
struct wd_alg_list {
    const char *alg_name;
    const char *drv_name;
    int priority;
    bool available;
    int refcnt;

    struct wd_alg_driver *drv;
    struct wd_alg_list *next;
};

struct wd_alg_driver *wd_request_drv(const char *alg_name, bool hw_mask);
void wd_release_drv(struct wd_alg_driver *drv);
```

​    The southbound driver interface is unified, no longer differentiated according to the algorithm class, and the user-mode driver is triggered through dlopen to perform a unified registration operation.

```
struct wd_alg_driver {
    const char  *drv_name;
    const char  *alg_name;
    int priority;
    int queue_num;
    int op_type_num;
    int priv_size;
    handle_t fallback;

    int (*init)(void *conf, void *priv);
    void (*exit)(void *priv);
    int (*send)(handle_t ctx, void *drv_msg);
    int (*recv)(handle_t ctx, void *drv_msg);
    int  (*get_usage)(void *param);
};

int wd_alg_driver_register(struct wd_alg_driver *drv);
void wd_alg_driver_unregister(struct wd_alg_driver *drv);
```

​    When the control layer process is initialized, directly load all device driver so files in the specified directory through dlopen, and guide the device driver to register on the algorithm list.

​    The user queries the supported algorithm driver from the algorithm list according to the specified algorithm, and finds the optimal device driver for use according to the priority.

​	In order to match the device resources on the uacce framework based on the algorithm class declaration method, it is necessary to map through the corresponding matching function, obtain the corresponding algorithm class through the algorithm name, and then perform resource application and mapping operations on the device:

```
static struct acc_alg_item alg_options[] = {
    {"zlib", "zlib-deflate"},
    {"gzip", "gzip"},
    {"deflate", "deflate"},
    {"lz77_zstd", "lz77_zstd"},

    {"rsa", "rsa"},
    {"dh", "dh"},
    {"ecdh", "ecdh"},
    {"x25519", "x25519"},
    {"x448", "x448"},
    {"ecdsa", "ecdsa"},
    {"sm2", "sm2"},
    ...
    {"", ""}
};

static void wd_get_alg_type(const char *alg_name, char *alg_type)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(alg_options); i++) {
        if (strcmp(alg_name, alg_options[i].name) ==3D 0) {
            (void)strcpy(alg_type, alg_options[i].algtype);
            break;
        }
    }
}
```

​    At the same time, when the corresponding algorithm module allocates sessions, it needs to check whether the device drivers and resources applied for through the sub-algorithm support the current algorithm, and only those that pass the check can continue to execute the task：

```
int wd_drv_alg_support(const char *alg_name,
    struct wd_alg_driver *drv)
{
    struct wd_alg_list *head = &alg_list_head;
    struct wd_alg_list *pnext = head->next;

    while (pnext) {
        if (!strcmp(alg_name, pnext->alg_name) &&
            !strcmp(drv->drv_name, pnext->drv_name)) {
            return true;
        }
        pnext = pnext->next;
    }

    return false;
}
```

​	In the specific implementation of the function code, the algorithm matching check is required when the session is allocated:

```
handle_t wd_cipher_alloc_sess(struct wd_cipher_sess_setup *setup)
{
    struct wd_cipher_sess *sess = NULL;
    int ret;

    ...
    sess->alg_name = wd_cipher_alg_name[setup->alg][setup->mode];
    sess->alg = setup->alg;
    sess->mode = setup->mode;
    ret = wd_drv_alg_support(sess->alg_name, wd_cipher_setting.driver);
    if (ret) {
        WD_ERR("failed to support this algorithm: %s!\n", sess->alg_name);
        goto err_sess;
    }

    ...
    return (handle_t)sess;

err_sess:
    if (sess->sched_key)
        free(sess->sched_key);
    free(sess);
    return (handle_t)0;
}
```



### **Modular Dynamic Loading Design：**
​		In order to eliminate the strong coupling between the previous API layer and the user mode driver layer, an algorithm support list component is added. This list is placed on a public framework. When users use the resource allocation interface to apply for resources, they will query the device driver according to the algorithm name. And in the acquisition process, the optimal device driver is searched by priority.

<svg xmlns:ev="http://www.w3.org/2001/xml-events" width="1000" xmlns:xlink="http://www.w3.org/1999/xlink" height="380" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2255 804"><style type="text/css"><![CDATA[
.st2 {fill:#000000;font-family:=E5=AE=8B=E4=BD=93;font-size:18pt}
.st1 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:10pt}
.st4 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:14pt}
.st3 {fill:#1f6391;font-family:=E5=AE=8B=E4=BD=93;font-size:10pt}
.st6 {fill:#1f6391;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
.st5 {fill:#1f6391;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:14pt}
]]></style><defs/><g transform="translate(5,5)" id="page1"><rect x="0" stroke="#808080" fill="#ffffff" width="2245" height="794" y="0"/><g transform="translate(701.64,305.67)"><path d="M100.1,62L100.1,0L0,0L0,62L100.1,62z" stroke="#3498db" fill="#00b050" id="shape1"/><text class="st1"><tspan x="8.1" y="16.5">alg_name:x1x</tspan><tspan x="8.1" y="35.5">alg driver;</tspan><tspan x="8.1" y="54.5">next;</tspan></text></g><g transform="translate(499.64,315.28)"><path d="M124.1,42.8L124.1,0L0,0L0,42.8L124.1,42.8z" stroke="#3498db" fill="#00b0f0" id="shape2"/><text class="st2"><tspan x="8.1" y="30.9">List_Head</tspan></text></g><g transform="translate(623.78,336.67)" id="shape3"><path d="M0,0L73.5,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M77.9,0L72.7,-3C73.2,-2.1,73.5,-1.1,73.5,0C73.5,1.1,73.2,2.1,72.7,3L77.9,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(879.64,305.67)"><path d="M100.1,62L100.1,0L0,0L0,62L100.1,62z" stroke="#3498db" fill="#00b050" id="shape4"/><text class="st1"><tspan x="8.1" y="16.5">alg_name:x2x</tspan><tspan x="8.1" y="35.5">alg driver;</tspan><tspan x="8.1" y="54.5">next;</tspan></text></g><g transform="translate(801.78,336.67)" id="shape5"><path d="M0,0L73.5,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M77.9,0L72.7,-3C73.2,-2.1,73.5,-1.1,73.5,0C73.5,1.1,73.2,2.1,72.7,3L77.9,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1056.64,305.67)"><path d="M100.1,62L100.1,0L0,0L0,62L100.1,62z" stroke="#3498db" fill="#00b050" id="shape6"/><text class="st1"><tspan x="8.1" y="16.5">alg_name:x2x</tspan><tspan x="8.1" y="35.5">alg driver;</tspan><tspan x="8.1" y="54.5">next;</tspan></text></g><g transform="translate(979.78,336.67)" id="shape7"><path d="M0,0L72.5,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M76.9,0L71.7,-3C72.2,-2.1,72.5,-1.1,72.5,0C72.5,1.1,72.2,2.1,71.7,3L76.9,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(681.82,169.52)"><path d="M140.4,60.3L140.4,0L0,0L0,60.3L140.4,60.3z" stroke="#3498db" fill="#92d050" id="shape8"/><text class="st2"><tspan x="10.2" y="39.6">libxx1_drv</tspan></text></g><g transform="translate(958.82,169.52)"><path d="M140.4,60.3L140.4,0L0,0L0,60.3L140.4,60.3z" stroke="#3498db" fill="#92d050" id="shape9"/><text class="st2"><tspan x="10.2" y="39.6">libxx2_drv</tspan></text></g><g transform="translate(1235.82,169.52)"><path d="M140.4,60.3L140.4,0L0,0L0,60.3L140.4,60.3z" stroke="#3498db" fill="#92d050" id="shape10"/><text class="st2"><tspan x="10.2" y="39.6">libxx3_drv</tspan></text></g><g transform="translate(1235.81,305.67)"><path d="M100.1,62L100.1,0L0,0L0,62L100.1,62z" stroke="#3498db" fill="#00b050" id="shape11"/><text class="st1"><tspan x="8.1" y="16.5">alg_name:x3x</tspan><tspan x="8.1" y="35.5">alg driver;</tspan><tspan x="8.1" y="54.5">next;</tspan></text></g><g transform="translate(1156.78,336.67)" id="shape12"><path d="M0,0L74.6,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M79,0L73.8,-3C74.3,-2.1,74.6,-1.1,74.6,0C74.6,1.1,74.3,2.1,73.8,3L79,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1414.99,305.67)"><path d="M100.1,62L100.1,0L0,0L0,62L100.1,62z" stroke="#3498db" fill="#00b050" id="shape13"/><text class="st1"><tspan x="8.1" y="16.5">alg_name:x3x</tspan><tspan x="8.1" y="35.5">alg driver;</tspan><tspan x="8.1" y="54.5">next;</tspan></text></g><g transform="translate(752.02,229.82)" id="shape14"><path d="M0,0L-0.3,71.5" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M-0.3,75.8L2.7,70.7C1.8,71.2,.8,71.5,-0.3,71.5C-1.4,71.5,-2.4,71.2,-3.3,70.6L-0.3,75.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="-28" fill="#ffffff" width="57.2" height="15" y="30.4"/><text class="st3"><tspan x="-28.2" y="42.4">register</tspan></text></g><g transform="translate(1029.02,229.82)" id="shape15"><path d="M0,0L-95.8,73.2" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M-99.3,75.8L-93.4,75.1C-94.3,74.7,-95.2,74.1,-95.8,73.2C-96.5,72.3,-96.9,71.3,-97,70.3L-99.3,75.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="-77.5" fill="#ffffff" width="57.2" height="15" y="30.4"/><text class="st3"><tspan x="-77.7" y="42.4">register</tspan></text></g><g transform="translate(1029.02,229.82)" id="shape16"><path d="M0,0L74.5,72.8" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M77.7,75.8L76.1,70.1C75.8,71.1,75.3,72,74.5,72.8C73.8,73.6,72.9,74.1,71.9,74.4L77.7,75.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="11" fill="#ffffff" width="57.2" height="15" y="30.4"/><text class="st3"><tspan x="10.8" y="42.4">register</tspan></text></g><g transform="translate(1306.02,229.82)" id="shape17"><path d="M0,0L-19,71.6" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M-20.1,75.8L-15.9,71.6C-16.9,71.9,-18,71.9,-19,71.6C-20.1,71.3,-21,70.8,-21.7,70.1L-20.1,75.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="-38" fill="#ffffff" width="57.2" height="15" y="30.4"/><text class="st3"><tspan x="-38.1" y="42.4">register</tspan></text></g><g transform="translate(1306.02,229.82)" id="shape18"><path d="M0,0L155.1,74" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M159,75.8L155.6,70.9C155.7,71.9,155.5,73,155.1,74C154.6,74.9,153.9,75.7,153.1,76.3L159,75.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="51.6" fill="#ffffff" width="57.2" height="15" y="30.4"/><text class="st3"><tspan x="51.5" y="42.4">register</tspan></text></g><g transform="translate(1335.95,336.67)" id="shape19"><path d="M0,0L74.6,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M79,0L73.8,-3C74.4,-2.1,74.6,-1.1,74.6,0C74.6,1.1,74.4,2.1,73.8,3L79,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(246.01,167.25)"><path d="M180.5,64.9L180.5,0L0,0L0,64.9L180.5,64.9z" stroke="#3498db" fill="#92d050" id="shape20"/><text class="st2"><tspan x="54.2" y="41.9">WD API</tspan></text></g><g transform="translate(31.51,180.67)" id="shape21"><text class="st4"><tspan x="26.3" y="25.5">control cmd</tspan></text></g><path d="M4.4,64.6L4.4,9L0,9L8.9,0L17.7,9L13.3,9L13.3,64.6L4.4,64.6z" stroke="#dd7195" fill="#dd7195" transform="matrix(0,1,-1,0,239.4,194.4)" id="shape22"/><g transform="translate(426.49,199.67)" id="shape23"><path d="M0,0L250.9,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M255.3,0L250.1,-3C250.6,-2.1,250.9,-1.1,250.9,0C250.9,1.1,250.6,2.1,250.1,3L255.3,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="95.8" fill="#ffffff" width="65.4" height="25" y="-12.5"/><text class="st5"><tspan x="95.7" y="6.5">dlopen</tspan></text></g><g transform="translate(822.22,199.67)" id="shape24"><path d="M0,0L132.2,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M136.6,0L131.4,-3C131.9,-2.1,132.2,-1.1,132.2,0C132.2,1.1,131.9,2.1,131.4,3L136.6,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1099.22,199.67)" id="shape25"><path d="M0,0L132.2,0" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M136.6,0L131.4,-3C131.9,-2.1,132.2,-1.1,132.2,0C132.2,1.1,131.9,2.1,131.4,3L136.6,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><path d="M0,0L532.9,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,466,695.1)" stroke-width="2" id="shape26"/><g transform="translate(248.01,619.54)"><path d="M178.5,68.3L178.5,0L0,0L0,68.3L178.5,68.3z" stroke="#3498db" fill="#00b0f0" id="shape27"/><text class="st2"><tspan x="47.2" y="43.6">ALG API</tspan></text></g><g transform="translate(31.51,634.67)" id="shape28"><text class="st4"><tspan x="27.3" y="25.5">data stream</tspan></text></g><path d="M13.2,5.5L62.8,5.5L62.8,0L76,11L62.8,22L62.8,16.5L13.2,16.5L13.2,22L0,11L13.2,0L13.2,5.5z" stroke="#2da2bf" fill="#2da2bf" transform="translate(169.05,642.67)" id="shape29"/><g transform="translate(556.24,634.67)"><path d="M316.5,38L316.5,0L0,0L0,38L316.5,38z" stroke="#3498db" fill="#92d050" id="shape30"/><text class="st2"><tspan x="20.3" y="28.5">libwd_crypto/libwd_comp</tspan></text></g><g transform="translate(1235.81,625.17)"><path d="M156.2,57L156.2,0L0,0L0,57L156.2,57z" stroke="#3498db" fill="#7eccb6" id="shape31"/><text class="st2"><tspan x="18.1" y="38">driver ops</tspan></text></g><path d="M0,0L532.9,0" stroke="#236ea1" stroke-dasharray="2,5" fill="none" transform="matrix(0,-1,1,0,1537,679.1)" stroke-width="2" id="shape32"/><g transform="translate(1576.06,625.18)"><path d="M200.7,54.1L200.7,0L0,0L0,54.1L200.7,54.1z" stroke="#3498db" fill="#00b0f0" id="shape33"/><text class="st2"><tspan x="58.4" y="36.6">ACC dev</tspan></text></g><g transform="translate(714.5,634.67)" id="shape34"><path d="M0,0L-150.7,-272.8" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M-152.8,-276.6L-152.9,-270.6C-152.4,-271.5,-151.6,-272.2,-150.7,-272.8C-149.7,-273.3,-148.7,-273.5,-147.7,-273.5L-152.8,-276.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><rect x="-90.3" fill="#ffffff" width="28.6" height="15" y="-145.8"/><text class="st3"><tspan x="-90.4" y="-133.8">find</tspan></text></g><g transform="translate(1106.71,367.67)" id="shape35"><path d="M0,0L204.4,254.1" stroke="#236ea1" stroke-dasharray="11,5,2.5,5" fill="none"/><path stroke-linecap="round" d="M207.2,257.5L206.3,251.6C205.9,252.5,205.3,253.4,204.4,254.1C203.6,254.8,202.6,255.2,201.6,255.3L207.2,257.5" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(426.49,653.67)" id="shape36"><path d="M9.8,0L120,0" stroke="#236ea1" fill="none" stroke-width="2.66667"/><path stroke-linecap="round" d="M9.8,4.9L0,0L9.8,-4.9L9.8,4.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M120,-4.9L129.8,0L120,4.9L120,-4.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(872.76,653.67)" id="shape37"><path d="M9.8,0L353.3,0" stroke="#236ea1" fill="none" stroke-width="2.66667"/><path stroke-linecap="round" d="M9.8,4.9L0,0L9.8,-4.9L9.8,4.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M353.3,-4.9L363.1,0L353.3,4.9L353.3,-4.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(1391.96,653.67)" id="shape38"><path d="M9.8,-0.1L174.3,-1.3" stroke="#236ea1" fill="none" stroke-width="2.66667"/><path stroke-linecap="round" d="M9.8,4.8L0,0L9.8,-5L9.8,4.8" stroke="#236ea1" fill="#236ea1" stroke-width="1"/><path stroke-linecap="round" d="M174.3,-6.2L184.1,-1.4L174.3,3.6L174.3,-6.2" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(499.64,98.6)" id="shape39"><text class="st6"><tspan x="4.1" y="9.1">Find the "so" file from the fixed directory, and detect whether </tspan><tspan x="4.1" y="30.1">the "so" internal interface has a driver registration interface </tspan><tspan x="4.1" y="51.1">wd_alg_driver_register()</tspan></text></g></g></svg>
​		In order to query the corresponding device driver files more accurately, you can query the user mode driver so file in the system dynamic library directory. Then check whether it contains an algorithm-driven registration interface, and if there is a corresponding interface, open it through dlopen. The algorithm registration operation will be triggered during the opening process, and then the algorithms supported by the device driver will be registered on the algorithm list.

​		The complete dynamic loading processing flow is shown in the following figure:

<svg xmlns:ev="http://www.w3.org/2001/xml-events" width="755" xmlns:xlink="http://www.w3.org/1999/xlink" height="813" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1133 1220"><style type="text/css"><![CDATA[
.st2 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
.st5 {fill:#000000;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:14pt}
.st4 {fill:#1f6391;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
.st1 {fill:#ffffff;font-family:=E5=BE=AE=E8=BD=AF=E9=9B=85=E9=BB=91;font-size:12pt}
.st3 {fill:#ffffff}
]]></style><defs/><g transform="translate(5,5)" id="page1"><rect x="0" stroke="#808080" fill="#ffffff" width="1123" height="1587" y="0"/><g transform="translate(449.5,50)"><path d="M20,40L74,40C85,40,94,31,94,20C94,9,85,0,74,0L20,0C9,0,0,9,0,20C0,31,9,40,20,40z" stroke="#83b3e3" fill="#2d85c1" id="shape1"/><text class="st1"><tspan x="30" y="25.5">start</tspan></text></g><g transform="translate(419,128)"><path d="M156,37L156,0L0,0L0,37L156,37z" stroke="#83b3e3" fill="#2d85c1" id="shape2"/><text class="st1"><tspan x="31" y="24">wd_xxx_init2</tspan></text></g><g transform="translate(496.5,90)" id="shape3"><path d="M0,0L.4,33.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M.5,38L3.4,32.8C2.6,33.3,1.5,33.6,.4,33.6C-0.7,33.6,-1.7,33.3,-2.6,32.8L.5,38" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(450,1159)"><path d="M20,40L74,40C85,40,94,31,94,20C94,9,85,0,74,0L20,0C9,0,0,9,0,20C0,31,9,40,20,40z" stroke="#83b3e3" fill="#2d85c1" id="shape4"/><text class="st1"><tspan x="33" y="25.5">end</tspan></text></g><g transform="translate(419,210.5)"><path d="M156,37L156,0L0,0L0,37L156,37z" stroke="#83b3e3" fill="#2d85c1" id="shape5"/><text class="st1"><tspan x="21" y="24">wd_dlopen_drv</tspan></text></g><g transform="translate(497,165)" id="shape6"><path d="M0,0L0,41.1" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,45.5L3,40.3C2.1,40.8,1.1,41.1,0,41.1C-1.1,41.1,-2.1,40.8,-3,40.3L0,45.5" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(382.2,584.15)"><path d="M114.8,59.7L229.6,29.9L114.8,0L0,29.9L114.8,59.7z" stroke="#83b3e3" fill="#2d85c1" id="shape7"/><text class="st1"><tspan x="45.3" y="35.4">wd_ctx_param_init</tspan></text></g><g transform="translate(497,643.85)" id="shape8"><path d="M0,0L0,54.8" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,59.2L3,54C2.1,54.5,1.1,54.8,0,54.8C-1.1,54.8,-2.1,54.5,-3,54L0,59.2" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(497,762.78)" id="shape9"><path d="M0,0L0,391.8" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,396.2L3,391C2.1,391.5,1.1,391.8,0,391.8C-1.1,391.8,-2.1,391.5,-3,391L0,396.2" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(419,437.5)"><path d="M156,37L156,0L0,0L0,37L156,37z" stroke="#83b3e3" fill="#2d85c1" id="shape10"/><text class="st1"><tspan x="16" y="24">wd_alg_drv_bind</tspan></text></g><g transform="translate(647,211.5)"><path d="M187.3,35.8L187.3,0L0,0L0,35.8L187.3,35.8z" stroke="#83b3e3" fill="#92d050" id="shape11"/><text class="st1"><tspan x="18.1" y="23.4">wd_get_lib_file_path</tspan></text></g><g transform="translate(575,229)" id="shape12"><path d="M0,0L40,0L67.6,.3" stroke="#236ea1" stroke-dasharray="11,5" fill="none"/><path stroke-linecap="round" d="M72,.4L66.8,-2.7C67.3,-1.8,67.6,-0.7,67.6,.3C67.6,1.4,67.3,2.5,66.8,3.3L72,.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(740.63,247.3)" id="shape13"><path d="M0,0L0,14.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,19L3,13.8C2.1,14.3,1.1,14.6,0,14.6C-1.1,14.6,-2.1,14.3,-3,13.8L0,19" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(611.8,732.93)" id="shape14"><path d="M0,0L38.9,0" stroke="#236ea1" stroke-dasharray="11,5" fill="none"/><path stroke-linecap="round" d="M43.3,0L38.1,-3C38.6,-2.1,38.9,-1.1,38.9,0C38.9,1.1,38.6,2.1,38.1,3L43.3,0" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(740.63,302)" id="shape15"><path d="M0,0L0,14.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,19L3,13.8C2.1,14.3,1.1,14.6,0,14.6C-1.1,14.6,-2.1,14.3,-3,13.8L0,19" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(575,456)" id="shape16"><path d="M0,0L47.3,0L74.9,-0.3" stroke="#236ea1" stroke-dasharray="11,5" fill="none"/><path stroke-linecap="round" d="M79.3,-0.4L74,-3.3C74.5,-2.5,74.9,-1.4,74.9,-0.3C74.9,.7,74.6,1.8,74.1,2.7L79.3,-0.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(497,474.5)" id="shape17"><path d="M0,0L0,105.3" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,109.6L3,104.5C2.1,105,1.1,105.3,0,105.3C-1.1,105.3,-2.1,105,-3,104.5L0,109.6" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(164,544)"><path d="M156,37L156,0L0,0L0,37L156,37z" stroke="#83b3e3" fill="#2d85c1" id="shape18"/><text class="st1"><tspan x="21" y="24">wd_disable_drv</tspan></text></g><g transform="translate(164,468)"><path d="M156,37L156,0L0,0L0,37L156,37z" stroke="#83b3e3" fill="#2d85c1" id="shape19"/><text class="st1"><tspan x="6" y="24">wd_alg_drv_unbind</tspan></text></g><g transform="translate(242,544)" id="shape20"><path d="M0,0L0,-34.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,-39L-3,-33.8C-2.1,-34.3,-1.1,-34.6,0,-34.6C1.1,-34.6,2.1,-34.3,3,-33.8L0,-39" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(382.2,614)" id="shape21"><path d="M0,0L-140.2,0L-140.2,-28.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-140.2,-33L-143.2,-27.8C-142.3,-28.3,-141.3,-28.6,-140.2,-28.6C-139.1,-28.6,-138.1,-28.3,-137.2,-27.8L-140.2,-33" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(242,468)" id="shape22"><path d="M0,0L0,-80.3L250.6,-80.3" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M255,-80.3L249.8,-83.3C250.3,-82.4,250.6,-81.4,250.6,-80.3C250.6,-79.2,250.3,-78.2,249.8,-77.3L255,-80.3" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(382.2,703.07)"><path d="M114.8,59.7L229.6,29.9L114.8,0L0,29.9L114.8,59.7z" stroke="#83b3e3" fill="#2d85c1" id="shape23"/><text class="st1"><tspan x="52.3" y="35.4">wd_alg_attrs_init</tspan></text></g><g transform="translate(382.2,732.93)" id="shape24"><path d="M0,0L-140.2,0L-140.2,-147.5" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-140.2,-151.9L-143.2,-146.7C-142.3,-147.2,-141.3,-147.5,-140.2,-147.5C-139.1,-147.5,-138.1,-147.2,-137.2,-146.7L-140.2,-151.9" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(662.63,321)"><path d="M156,35.7L156,0L0,0L0,35.7L156,35.7z" stroke="#83b3e3" fill="#92d050" id="shape25"/><text class="st1"><tspan x="52" y="23.4">dlopen</tspan></text></g><g transform="translate(662.63,266.3)"><path d="M156,35.7L156,0L0,0L0,35.7L156,35.7z" stroke="#83b3e3" fill="#92d050" id="shape26"/><text class="st1"><tspan x="54" y="23.4">dladdr</tspan></text></g><g transform="translate(655.13,715.03)"><path d="M171,35.8L171,0L0,0L0,35.8L171,35.8z" stroke="#83b3e3" fill="#92d050" id="shape27"/><text class="st1"><tspan x="23" y="23.4">wd_get_alg_type</tspan></text></g><g transform="translate(655.13,776.8)"><path d="M171.1,35.8L171.1,0L0,0L0,35.8L171.1,35.8z" stroke="#83b3e3" fill="#92d050" id="shape28"/><text class="st1"><tspan x="18.1" y="23.4">wd_sched_rr_alloc</tspan></text></g><g transform="translate(655.13,838.58)"><path d="M172.1,35.8L172.1,0L0,0L0,35.8L172.1,35.8z" stroke="#83b3e3" fill="#92d050" id="shape29"/><text class="st1"><tspan x="30.1" y="23.4">wd_alg_ctx_init</tspan></text></g><g transform="translate(654.26,900.35)"><path d="M172.9,35.8L172.9,0L0,0L0,35.8L172.9,35.8z" stroke="#83b3e3" fill="#92d050" id="shape30"/><text class="st1"><tspan x="5.4" y="23.4">wd_sched_rr_instance</tspan></text></g><g transform="translate(740.63,750.82)" id="shape31"><path d="M0,0L0,10L0,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M.1,26L3,20.8C2.2,21.3,1.1,21.6,0,21.6C-1,21.6,-2.1,21.3,-3,20.8L.1,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(740.69,812.6)" id="shape32"><path d="M0,0L0,10L.4,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M.5,26L3.3,20.7C2.5,21.2,1.5,21.6,.4,21.6C-0.7,21.6,-1.8,21.4,-2.7,20.9L.5,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(741.19,874.38)" id="shape33"><path d="M0,0L0,10L-0.4,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0.5,26L2.7,20.9C1.8,21.4,.7,21.6,-0.4,21.6C-1.5,21.6,-2.5,21.2,-3.3,20.7L-0.5,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(654.13,962.13)"><path d="M173,35.8L173,0L0,0L0,35.8L173,35.8z" stroke="#83b3e3" fill="#0070c0" id="shape34"/><text class="st2"><tspan class="st3" x="39" y="23.4">alg_init_func</tspan></text></g><g transform="translate(740.69,936.15)" id="shape35"><path d="M0,0L0,10L-0,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0.1,26L3,20.8C2.1,21.3,1,21.6,-0,21.6C-1.1,21.6,-2.2,21.3,-3,20.8L-0.1,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(497,247.5)" id="shape36"><path d="M0,0L0,185.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,190L3,184.8C2.1,185.3,1.1,185.6,0,185.6C-1.1,185.6,-2.1,185.3,-3,184.8L0,190" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(493.26,648.7)" id="shape37"><text class="st4"><tspan x="11.4" y="17">Y</tspan></text></g><g transform="translate(493.26,776.8)" id="shape38"><text class="st4"><tspan x="11.4" y="17">Y</tspan></text></g><g transform="translate(334.26,584.15)" id="shape39"><text class="st4"><tspan x="10.4" y="17">N</tspan></text></g><g transform="translate(334.26,703.07)" id="shape40"><text class="st4"><tspan x="10.4" y="17">N</tspan></text></g><g transform="translate(172.51,61.67)" id="shape41"><text class="st5"><tspan x="4.3" y="13">Dynamic loading </tspan><tspan x="47.3" y="38">process</tspan></text></g><g transform="translate(654.26,437.7)"><path d="M171,35.8L171,0L0,0L0,35.8L171,35.8z" stroke="#83b3e3" fill="#92d050" id="shape42"/><text class="st1"><tspan x="27" y="23.4">wd_request_drv</tspan></text></g><g transform="translate(654.26,499.7)"><path d="M171,35.8L171,0L0,0L0,35.8L171,35.8z" stroke="#83b3e3" fill="#92d050" id="shape43"/><text class="st1"><tspan x="27" y="12.9">wd_request_drv</tspan><tspan x="51" y="33.9">(fallback)</tspan></text></g><g transform="translate(739.76,473.5)" id="shape44"><path d="M0,0L0,21.8" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,26.2L3,21C2.1,21.5,1.1,21.8,0,21.8C-1.1,21.8,-2.1,21.5,-3,21L0,26.2" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(662.63,377.1)"><path d="M156,35.7L156,0L0,0L0,35.7L156,35.7z" stroke="#83b3e3" fill="#92d050" id="shape45"/><text class="st1"><tspan x="56" y="23.4">dlsym</tspan></text></g><g transform="translate(740.63,356.7)" id="shape46"><path d="M0,0L0,16" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,20.4L3,15.2C2.1,15.7,1.1,16,0,16C-1.1,16,-2.1,15.7,-3,15.2L0,20.4" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(655.13,1023.9)"><path d="M172.1,35.8L172.1,0L0,0L0,35.8L172.1,35.8z" stroke="#83b3e3" fill="#92d050" id="shape47"/><text class="st1"><tspan x="17.1" y="23.4">wd_init_ctx_config</tspan></text></g><g transform="translate(655.13,1085.68)"><path d="M172.1,35.8L172.1,0L0,0L0,35.8L172.1,35.8z" stroke="#83b3e3" fill="#92d050" id="shape48"/><text class="st1"><tspan x="34.1" y="23.4">wd_init_sched</tspan></text></g><g transform="translate(655.13,1147.45)"><path d="M172.1,35.8L172.1,0L0,0L0,35.8L172.1,35.8z" stroke="#83b3e3" fill="#92d050" id="shape49"/><text class="st1"><tspan x="19.1" y="23.4">wd_alg_init_driver</tspan></text></g><g transform="translate(740.63,997.93)" id="shape50"><path d="M0,0L0,10L.4,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M.6,26L3.4,20.7C2.5,21.2,1.5,21.5,.4,21.6C-0.7,21.6,-1.7,21.4,-2.6,20.9L.6,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(741.19,1059.7)" id="shape51"><path d="M0,0L-0,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M-0,26L3,20.8C2.1,21.3,1.1,21.6,-0,21.6C-1.1,21.6,-2.1,21.3,-3,20.8L-0,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g><g transform="translate(741.19,1121.48)" id="shape52"><path d="M0,0L0,21.6" stroke="#236ea1" fill="none"/><path stroke-linecap="round" d="M0,26L3,20.8C2.1,21.3,1.1,21.6,0,21.6C-1.1,21.6,-2.1,21.3,-3,20.8L0,26" stroke="#236ea1" fill="#236ea1" stroke-width="1"/></g></g></svg>
​		When registering an algorithm, it is distinguished whether it is software computing or hardware computing. Software computing is directly registered, and hardware computing is to detect whether the current algorithm is supported by the corresponding device during registration. If the supported device exists, register it, otherwise skip it.

​		When the normal task is sent, according to the algorithm device driver dynamically found from the algorithm list when the device resource is initialized, the task data is sent to the corresponding device driver through the unified driver ops. Then send the data to the accelerator device through the encapsulation interface driven by the device, and obtain the data processing result after the processing is completed.

​		In order to realize the dynamic loading function of the device driver, the device driver will be adapted through a unified driver ops, and an independent driver so library file will be compiled and generated. Deploy the driver's so file to the system dynamic library file directory on the server that needs to use UADK, and then automatically open and load it through the dlopen method inside the resource initialization interface. When loading the driver library file, the supported algorithm will be triggered to register to the algorithm List.

​		In addition, on the basis of the original model that supports hardware acceleration alone, software computing supplementary support is provided in the driver through the fallback method. Implement software and hardware hybrid computing support.

### **Implementation Plan Description**
​		Through the update of the init2 interface, the adaptation and initialization of dynamic loading are realized. At the same time, a pair of new initialization interfaces will be added. The cipher module corresponds to the newly added interface:

```
int wd_cipher_init2(char *alg, __u32 sched_type, int task_type, struct wd_ctx_params *ctx_params);

#define wd_cipher_init2_(alg, sched_type, task_type) \
    wd_cipher_init2(alg, sched_type, task_type, NULL)

void wd_comp_uninit2(void);
```

​		Other parts remain basically unchanged to ensure compatibility and use with the original framework. But the initialization will be processed internally, and the initialization interface will be reused:

```
int wd_cipher_init2(char *alg, __u32 sched_type, int task_type,
struct wd_ctx_params *ctx_params)
{
    struct wd_ctx_nums cipher_ctx_num[WD_CIPHER_DECRYPTION + 1] = {0};
    struct wd_ctx_params cipher_ctx_params = {0};
    enum wd_status status;
    int i, ret = 0;
    bool flag;

	=E2=80=A6
    wd_cipher_setting.dlh_list = wd_dlopen_drv(NULL);
    if (!wd_cipher_setting.dlh_list) {
        WD_ERR("fail to open driver lib files.\n");
        goto out_uninit;
    }

res_retry:
    memset(&wd_cipher_setting.config, 0, sizeof(struct wd_ctx_config_internal));
    /* Get alg driver and dev name */
    wd_cipher_setting.driver = wd_alg_drv_bind(task_type, alg);
    if (!wd_cipher_setting.driver) {
        WD_ERR("fail to bind a valid driver.\n");
        goto out_dlopen;
    }

    cipher_ctx_params.bmp = NULL;
    cipher_ctx_params.ctx_set_num = cipher_ctx_num;
    cipher_ctx_params.op_type_num = wd_cipher_setting.driver->op_type_num;
    if (cipher_ctx_params.op_type_num > WD_CIPHER_DECRYPTION + 1) {
        WD_ERR("fail to check driver op type numbers.\n");
        wd_disable_drv(wd_cipher_setting.driver);
        goto res_retry;
    }
    for (i = 0; i < cipher_ctx_params.op_type_num; i++) {
        cipher_ctx_num[i].sync_ctx_num = wd_cipher_setting.driver->queue_num;
        cipher_ctx_num[i].async_ctx_num = wd_cipher_setting.driver->queue_num;
    }

    wd_cipher_init_attrs.alg = alg;
    wd_cipher_init_attrs.sched_type = sched_type;
    wd_cipher_init_attrs.driver = wd_cipher_setting.driver;
    wd_cipher_init_attrs.ctx_params = ctx_params ? ctx_params : &cipher_ctx_params;
    wd_cipher_init_attrs.alg_init = wd_cipher_init;
    wd_cipher_init_attrs.alg_poll_ctx = wd_cipher_poll_ctx;
    ret = wd_alg_attrs_init(&wd_cipher_init_attrs);
    if (ret) {
        if (ret ==3D -WD_ENODEV) {
            wd_disable_drv(wd_cipher_setting.driver);
            goto res_retry;
        }
        WD_ERR("fail to init alg attrs.\n");
        goto out_driver;
    }

    wd_alg_set_init(&wd_cipher_setting.status2);

    return 0;

out_driver:
    wd_alg_drv_unbind(wd_cipher_setting.driver);
out_dlopen:
    wd_dlclose_drv(wd_cipher_setting.dlh_list);
out_uninit:
    wd_alg_clear_init(&wd_cipher_setting.status2);
    return ret;
}
```

​    The uninitialization interface is also reused when releasing the current algorithm resources:

```
void wd_cipher_uninit2(void)
{
    wd_cipher_uninit();

    wd_alg_attrs_uninit(&wd_cipher_init_attrs);

    wd_alg_drv_release(wd_cipher_setting.driver);
    wd_dlclose_drv(wd_cipher_setting.dlh_list);
    wd_alg_clear_init(&wd_cipher_setting.status2);
}
```

​    Special attention is required. In order to maintain the commonality of each module, all internal resource initialization parts use public functions, and realize processing through a unified data structure:

```
struct wd_init_attrs {
    __u32 sched_type;
    char *alg;
    struct wd_alg_driver *driver;
    struct wd_sched *sched;
    struct wd_ctx_params *ctx_params;
    struct wd_ctx_config *ctx_config;
    wd_alg_init alg_init;
    wd_alg_poll_ctx alg_poll_ctx;
};
```

​    Moreover, the framework provides multiple internal public functions to complete the public processing of resource initialization:

```
int wd_alg_attrs_init(struct wd_init_attrs *alg_init_attrs);
void wd_alg_attrs_uninit(struct wd_init_attrs *attrs);

struct wd_alg_driver *wd_alg_drv_request(int task_type, char *alg_name);
void wd_alg_drv_release(struct wd_alg_driver *drv);

int wd_alg_init_driver(struct wd_ctx_config_internal *config,
    struct wd_alg_driver *driver, void **drv_priv);
void wd_alg_uninit_driver(struct wd_ctx_config_internal *config,
    struct wd_alg_driver *driver, void *drv_priv);

void *wd_dlopen_drv(const char *cust_lib_dir);
void wd_dlclose_drv(void *dlh_list);
```

​    Finally, the driver's fallback supports the initialization of the driver that performs software calculations synchronously when the algorithm is initialized:

```
static int wd_alg_init_fallback(struct wd_alg_driver *fb_driver)
{
    if (!fb_driver->init) {
        WD_ERR("soft sec driver have no init interface.\n");
        return -WD_EINVAL;
	}

	fb_driver->init(NULL, NULL);

    return 0;
}
```

```
static void wd_alg_uninit_fallback(struct wd_alg_driver *fb_driver)
{
    if (!fb_driver->exit) {
        WD_ERR("soft sec driver have no exit interface.\n");
        return;
    }

    fb_driver->exit(NULL);
}
```

​		When implemented inside the driver, the sending and receiving interface of the hardware computing can be used to call the software computing through the callback interface of the fallback to process the message.

### **Running Result Presentation**
​		Currently, the adaptation of the cipher algorithm of the SEC module and the algorithm of the ZIP module has been completed, and the uadk_tool has been adjusted accordingly. Through the test of uadk_tool, the current dynamic loading function test is normal:

```
[root@localhost libs_dy]# ./uadk_tool benchmark --alg aes-128-ecb --mode sva --opt 0 --sync --pktlen 1024 --seconds 5 --thread 1 --multi 1 --ctxnum 1 --prefetch
start UADK benchmark test.
start UADK benchmark test.
    [--algname]: aes-128-ecb
    [--mode]:    1
    [--optype]:  0
    [--syncmode]:0
    [--pktlen]:  1024
    [--seconds]: 5
    [--thread]:  1
    [--multi]:   1
    [--ctxnum]:  1
    [--algclass]:cipher
    [--acctype]: 0
    [--prefetch]:1
    [--engine]:
algname:        length:         perf:           iops:           CPU_rate:
aes-128-ecb     1024Bytes       430231.6KB/s    430.2Kops       99.80%
```

```
[root@localhost libs_dy]# ./uadk_tool benchmark --alg aes-128-cbc --mode sva --opt 0 --sync --pktlen 1024 --seconds 5 --thread 1 --multi 1 --ctxnum 1 --prefetch
start UADK benchmark test.
start UADK benchmark test.
    [--algname]: aes-128-cbc
    [--mode]:    1
    [--optype]:  0
    [--syncmode]:0
    [--pktlen]:  1024
    [--seconds]: 5
    [--thread]:  1
    [--multi]:   1
    [--ctxnum]:  1
    [--algclass]:cipher
    [--acctype]: 0
    [--prefetch]:1
    [--engine]:
algname:        length:         perf:           iops:           CPU_rate:
aes-128-cbc     1024Bytes       424744.6KB/s    424.7Kops       99.80%
```

```
[root@localhost libs_dy]# ./uadk_tool benchmark --alg zlib --mode sva --opt 0 --sync --pktlen 1024 --seconds 5 --thread 1 --multi 1 --ctxnum 1 --prefetch
start UADK benchmark test.
start UADK benchmark test.
    [--algname]: zlib
    [--mode]:    1
    [--optype]:  0
    [--syncmode]:0
    [--pktlen]:  1024
    [--seconds]: 5
    [--thread]:  1
    [--multi]:   1
    [--ctxnum]:  1
    [--algclass]:zlib
    [--acctype]: 2
    [--prefetch]:1
    [--engine]:
algname:        length:         perf:           iops:           CPU_rate:
zlib            1024Bytes       354857.8KB/s    354.9Kops       99.80%
compress data file: ./zip_1024.zlib has exist!
```

