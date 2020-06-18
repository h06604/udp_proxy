# UDP Proxy Manual
## Introduction
UDP Proxy is an application which has the ability to forward UDP packets. UDP Proxy can drop UDP packets and delay UDP packets to simulate the behavior on the network.

The link below includes the executable files both on Windows and Ubuntu.

https://drive.google.com/drive/folders/1xokqtxLMv7QU7a2I9mBvoUG62YIgdr-5?usp=sharing
## Windows
1. Open the command prompt.
2. Change the directory to udp_proxy directory.
3. Input the following command to execute "udp_proxy.exe".
``udp_proxy -p 10080 -s 127.0.0.1:11111 -y 5 -d 50``

## Ubuntu
1. Open the terminal.
2. Change the directory to udp_proxy directory.
3. Input the following command.
4. Install libevent library.
``sudo apt-get install -y libevent-2.0-5``
5. Modify file permission with the following command.
``chmod +x udp_proxy``
6. Program execution with the following command.
``./udp_proxy -p 10080 -s 127.0.0.1:11111 -y 5 -d 50``

## Mac
1. Press Command+Space and type ***Terminal*** and press ***enter/return*** key.
2. Run in Terminal app:
``ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)" < /dev/null 2> /dev/null``
and press ***enter/return*** key.
If the screen prompts you to enter a password, please enter your Mac's user password to continue. When you type the password, it won't be displayed on screen, but the system would accept it. So just type your password and press ENTER/RETURN key. Then wait for the command to finish.
3. Run:
``brew install libevent``

Done! You can now use libevent.

## Usage
* -p and -s are necessary parameters, and the rest are optional  parameters
![](https://i.imgur.com/yJWP5Ty.png)
* When both -d and -y are -1, it is a special usage


## Testing
### iperf
Testing with using iperf UDP. The transmission bandwidth is set to 10 Mbps.
* set delay 100ms
![](https://i.imgur.com/NbpeLGI.png)

* set delay 1000ms
![](https://i.imgur.com/M6fXIYv.png)

* set drop 20(5%)
![](https://i.imgur.com/HjSEvyR.png)

* set drop 5(20%)
![](https://i.imgur.com/k5QHpM9.png)

* set delay 100ms and set drop 5(20%)
![](https://i.imgur.com/R2virw0.png)

* set delay 1000ms and set drop 5(20%)
![](https://i.imgur.com/w4BLOn2.png)
### UDP socket
Testing with the UDP sockets. 

Note that for the examples below, the Socket client send multiple Hello messages to the Socket server, and the sequence of each transmission starting from 0, 1, ..., and so on. Hence, the socket client is expected to receive Hello 0, Hello 1, Hello 2, ... etc.


The UDP socket client sends “Hello” 10 times to the UDP socket server as shown in the picture below. **
![](https://i.imgur.com/zUO1MMx.png)

The following figures show the test results of the UDP proxy with different parameters.
* ***set drop 1/5 packet.***
UDP Proxy will drop one random packet when the UDP client sending five packets.
![](https://i.imgur.com/XJzvZy0.png)

* ***set delay 5ms.***
UDP Proxy defers packets for 5ms.
![](https://i.imgur.com/ixT2d8r.png)

* ***set delay 100ms.***
UDP Proxy defers packets for 100ms.
![](https://i.imgur.com/zolCAvY.png)

* ***set delay 100ms and set drop 5***
![](https://i.imgur.com/jJrufXw.png)


## Q&A
### Received port and Transmited port are different.
![](https://i.imgur.com/YI1QK0o.jpg =500x)
![](https://i.imgur.com/jZ49yfe.png =500x)
The practical topology is shown in Figure 1. According to the Wireshark, the reason why the UDP Proxy is not using the port 5406 to send packets to UDP socket server is because the UDP Proxy codes is using the port 5406 to receive packets from UDP socket client and using the different port (port 63782) to send packets to UDP socket server.

## Refernce
[Install libevent on Mac OSX](http://macappstore.org/libevent/)
[Install iperf on Mac OSX](http://macappstore.org/iperf/)

## Latest update May 21, 2020.
