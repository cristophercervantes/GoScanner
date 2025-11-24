# GoScanner - Find What's On Your Network

Hey there! I'm Cristopher from Tensor Security Academy, and this is
**GoScanner** - a little tool I built to help people explore their
networks. This is our first version (**v1.0**), and I'm pretty excited
to share it with you!

## What's This For?

Ever wondered what devices are connected to your Wi-Fi? Or wanted to
check if your web server has the right ports open? That's what GoScanner
does --- it helps you see what's happening on your network.

## Get Started (It's Easy)

If you have Go installed, just run:

``` bash
go install github.com/cristophercervantes/GoScanner/cmd/goscanner@latest
```

Then type `goscanner` in your terminal and you're good to go!

## Here's How I Use It

### Finding Devices

``` bash
# See everything on my local network
goscanner -target 192.168.1.0/24 -ping-only

# Check if my Raspberry Pi is awake
goscanner -target 192.168.1.25 -tcp-syn 22,80
```

### Checking Ports

``` bash
# Quick check of common ports
goscanner -target mywebsite.com -ports 80,443

# Scan my home server
goscanner -target 192.168.1.100 -ports 1-1000
```

## What's Working in This First Version

I built this to handle the basics:

-   Finding active devices on your network\
-   Checking which ports are open\
-   Seeing MAC addresses for devices on your local network\
-   Working with different target types --- single IPs, ranges, or whole
    subnets

It's not trying to be the most powerful scanner out there --- just
something reliable and easy to use.

## Why I Built This

I teach at Tensor Security Academy (check us out at
tensorsecurityacademy.com), and I wanted to create a tool that my
students could actually understand and use. Most network scanners feel
overwhelming --- I wanted something friendly.

This is that tool. It's the first version, so it might have some rough
edges, but it works for what I need it to do.

## Some Handy Tricks

``` bash
# Just list what you would scan (without actually scanning)
goscanner -list-targets 192.168.1.0/24

# Scan without checking if hosts are alive first
goscanner -target 192.168.1.1-50 -ports 22,80,443 -skip-discovery
```

## Found a Bug? Have an Idea?

This is **v1.0** --- the first release!\
If you find something that doesn't work right or have ideas to make it
better, you can reach us at:

**tensorsecurityacademy@gmail.com**

I'm especially interested in:

-   Bugs or unexpected behavior\
-   Features that would make your life easier\
-   Knowing if this tool is helpful for you

## One Important Note

Please only use this on networks you own or have permission to scan. Be
a good internet citizen!

------------------------------------------------------------------------

**GoScanner v1.0 --- A simple tool for curious people**\
*From your friends at Tensor Security Academy 🚀*
