---
author: Florian Idelberger
title: CTF Writeup - HackTheBox - Cyber Apocalypse 2023
date: 2023-03-24
draft: true
description: My writeup from participating in a bigger CTF
---

#CTF Writeup - HackTheBox - Cyber Apocalypse 2023

These last five days I participated in my first CTF,  partially because I wanted to get more comfortable with security and certain low level topics and the opportunity presented itself as some people in the channel of a hackerspace had asked for additional team members.

The Cyber Apocalypse event by HackTheBox was quite big, with 74 challenges, spannign five days, though we took it a bit easy and everybody just tried to solve what they felt most comfortable with or wanted to do. It was a lot of fun for sure, and I learned a lot. Below I will try to describe the challenges that I solved. These were all relatively easy, but maybe it is still helpful for some.

Despite blockchain being not as hyped anymore, there were blockchain challenges. As I did some testing and security work for Ethereum 

## Blockchain - Navigating the Unknown

For people unfamiliar with blockchain development, this challenge provided a Readme to give some basic pointers, which is rather unusual compared to all other challenges. Though even I learned something new as they mentioned a new rust based CLI tool (foundry-rs (https://book.getfoundry.sh/r)) which can be used for all aspects instead of using a testing framework or using remix-ide of web3.py manually. After getting to know it a bit, I found it really nice to use.

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
In addition you got two url:port key value pairs, one of which was the rpc url for the example blockchain, the other one was a small web service, f.e. usable with netcat (as also explained in the README) which provided you the necessary connection information for the blockchain, which was spawned in a docker container. This information always consisted of the private key, user address corresponding to that key, target contract, and setup contract. It also allowed you to restart the instance and to retrieve the flag if you satsified the target condition. The setup contract set up the target contract and was also used to see and check for the target condition.

In this first challenge, the goal was mainly to call a certain function with an integer parameter to set "version" to 10. With the setup contract and its `iSolved()` function, you could then check if this was successful.

The main annoying thing about that was that I had to decide which environment I wanted to use, which tooling and that I had to probably update it. In the end, I didn't really use web3.py, but used foundry-rs for executing transactions and for testing code based exercises (mainly the 3rd one) I used remix-ide, as this also allows for testing transactions on a virtual chain.

Foundry has separate tools, depending on what you need. For transactions, `cast` is the right tool. Such as `cast send <target contract> 0x... "updateSensor(uint256)" 0x10 --priv-key <privatekey> --rpc-url http://<ip>:<port>`

In some cases the value would have to be converted to a proper type and maybe even packed for the abi, but afaik in this case that was not necessary.

Subsequently, you can then check the if it worked and is recognized by calling `isSolved()` on the setup contract in the same way. Over the netcat service you could then get the flag, which did the same I assume.

## Blockchain - Shooting 101

Shooting 101 was slightly more involved, but only in so far that you had to perform three specific transactions in the right order.

As you can see based on the `require` conditions, the can only be performed in their predetermined order (based on the modifiers).


```
  1 contract ShootingArea {
  4       bool public firstShot;
    1     bool public secondShot;
    2     bool public thirdShot;
    3
    4     modifier firstTarget() {
    5         require(!firstShot && !secondShot && !thirdShot);
    6         _;
    7     }
    8
    9     modifier secondTarget() {
   10         require(firstShot && !secondShot && !thirdShot);
   11         _;
   12     }
   13
   14     modifier thirdTarget() {
   15         require(firstShot && secondShot && !thirdShot);
   16         _;
   17     }
   18
   19     receive() external payable secondTarget {
   20         secondShot = true;
   21     }
   22
   23     fallback() external payable firstTarget {
   24         firstShot = true;
   25     }
   26
   27     function third() public thirdTarget {
   28         thirdShot = true;
   29     }
```

For the first target, you had to trigger the fallback function. This meant that you f.e. send a transaction with a function signature that is not defined (or some other conditions that you could check in the docs). For the second target, you had to send an arbitrary amount of Ether, thereby triggering the `receive()` function. The third one was then a normal function call transaction if I remember correctly. Then again get the flag from netcat.

## Blockchain - The Art of deception

This one was labeled as one difficulty higher, but still only easy. Embarrassingly, this gave me more trouble than I would have thought. The target contract implements an authorization procedure and provides an external interface `Entrant`. While I briefly thought that maybe string comparison could somehow be broken, this is unlikely and definitely not easy. So I quickly decided that the external interface has to be the likely target, as there were no other likely options and why else would it be implemented as interface with an external function. Admittedly, I was a bit hesitant to start on it at first, because implementing the interface in another contract would mean that I would actually have to write code. ^^

```
pragma solidity ^0.8.18; // W: SPDX license identifier not provided in source file. Before publishing, consider adding a comme…
    1
    2
    3 interface Entrant {
    4     function name() external returns (string memory);
    5 }
    6
    7 contract HighSecurityGate {
    8
    9     string[] private authorized = ["Orion", "Nova", "Eclipse"];
   10     string public lastEntrant;
   11
   12     function enter() external {
   13         Entrant _entrant = Entrant(msg.sender);
   14
   15         require(_isAuthorized(_entrant.name()), "Intruder detected");
   16         lastEntrant = _entrant.name();
   17     }
   18
   19     function _isAuthorized(string memory _user) private view returns (bool){
   20         for (uint i; i < authorized.length; i++){
   21             if (strcmp(_user, authorized[i])){
   22                 return true;
   23             }
   24         }
   25         return false;
   26     }
   27
   28     function strcmp(string memory _str1, string memory _str2) public pure returns (bool){
   29         return keccak256(abi.encodePacked(_str1)) == keccak256(abi.encodePacked(_str2));
   30     }
   31 }
```

In a new contract, I then implmented EntrantFake, which instantiates the target contract to be able to call it and implements the Entrant interface and the name function for it.

In this case, the `Setup.sol` contract showed that it checked if lastEntrant was set to "Pandora".
The main thing that took me way too long was - I was at first conviced that if done right, maybe just implementing name and just returning the name "Pandora" should suffice somehow. In the end, I realized that within one call, separate calls to name can return different values if implemented that way, as the stack is the same. Thus the first time name is called, it can return a valid name, but the second time when last Entrant is set, it can return "Pandora".

By implementing this malicious name function and then calling the enter function in the target contract, the malicious name is then used as part of the target contract.

```
--1   pragma solidity ^0.8.18; // W: SPDX license identifier not provided in source file. Before publishing, consider adding a comme…
       // W: SPDX license identifier not provided in source file. Before publishing, consider adding a comment containing "SPDX-Lice…
    1
    2 import {HighSecurityGate, Entrant} from "./FortifiedPerimeter.sol";
    3
    4 contract EntrantFake is Entrant {
    5
    6     HighSecurityGate contractInstance = HighSecurityGate(0x50003d99be68c8C270dC1dD00aD42A277dfC6B8c);
    7     uint i = 0;
    8
    9     function name() external override returns (string memory) {
   10         string memory b = "";
   11         if (i  == 0) {
   12         b = "Orion";
   13         i = i + 1;
   14         } else {
   15         b = "Pandora";
   16         }
   17         return b;
   18     }
   19
   20     function test() external {
   21     contractInstance.enter();
   22
   23     }
   24 }
```
   
   Once lastEntrant is set, the flag could then be retrieved from the webservice. For trying different solutions, remix-ide and its virtual chain was very helpful. Really the best way to try these is with remix-ide.
   
Interesting addendum - because at first I thought there must be some way to do this without returning different things via name(), I researched a bit and asked ChatGPT. As I hear that's a thing these days. TBH, I was not impressed - especially on the Solidity code, it frequently gave just plain wrong answers and 

## Reversing - Needle in a haystack

This challenge gave you a binary to analyze. However, it was not even necessary to disassemble it or similar, as you could just past it to the `strings` utility, which then shows you all strings in the binary, including the flag needed to complete the challenge.

## Forensics - Alien Cradle

This challenge gave you a power shell script. In case you executed it, which would of course be a bad idea in most cases, it rickrolled you by opening the requisite video in your browser.
When actually looking at the source, it was immediately obvious that the flag was just being cocatenated. These separate parts could then just be pierced together. 

## Hardware - Critical Flight

This challenge gave you a set of gerber files, to open with a PCB design or viewing tool. These were not hidden in any way or similar, so if you knew or could somehow figure out with which tool to open them, this was really easy and quick. I just openend them with gerberview from KiCad, and the just went through each layers, where two of the contained one part of the flag each.

![](kicad.png)

# Partial Solves

I think some I solved at least partially. Of those, I share the ones that I find more interesting.

## Reversing - Hunting License Partial Solve

Because I got relatively far (I think) and I like this challenge, I wanted to include it anyway.

## Reversing - C Shells

## HW - Timed Transmission

