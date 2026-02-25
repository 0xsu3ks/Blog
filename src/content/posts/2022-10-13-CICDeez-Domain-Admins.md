---
title:  "CICDeez Domain Admins"
date:   2023-10-13
tags: [posts]
excerpt: "Pivoting from an external position to a domain compromise via CICD infrastructure."
---


# CI/CDeez Domain Admins

Recently I found myself in a situation that required me do some research into an attack path that is not very widely documented. So, I thought it would be a fun exercise, to make a PoC, document the steps in hopes to help other pentesters and red teamers achieve their goals or help blue teamers and those DevOps folk secure their infrastructure a bit better.

In this article there will be references to the target organization PORTPEQUA.LAB, this is fictional lab environment.

## What the heck is Artifactory, JFrog, Ansible, Ansible Tower, Ansible Automation Platform, Ansible Hub, RHEL…

Artifactory is a repository manager that organizes all of your binary resources, sort of like a Github but not quite. Think about every time you utilize a python script that calls different libraries and such, Artifactory or JFrog keeps those libraries in one central location. (I’ll talk more about this at the very end and how _this_ can be exploited for absolute domination)

Ansible is one of the “simplest” (unless you’re the one deploying it) ways to automate deployment and configuration of applications and IT infrastructure.

Ansible Controller a.k.a Ansible Tower is the GUI interface behind Ansible, you see Ansible is a CLI based tool but the folks over at Red Hat have a GUI of sorts to help make this process easier (again, unless you’re the one deploying it).

RHEL, is Red Hat Enterprise Linux, this is just a flavor of Linux companies use to deploy Linux infrastructure. It costs money.

Now that we’ve covered some of the key item’s discussed, lets walk through the scenario step by step from recon to initial compromise to lateral movement and ultimately domain admin.

## Some Light Recon

As any other red team begins, reconnaissance, the first step, is my favorite part. Shameless plug, I will speaking at BSides Orlando with a partner of mine on some recon methods we have used to identify some needles in the haystack type of findings, similar to one the found here. As I sat down at my desk with my cup of coffee and began searching the internet for anything that can be useful, I came across a stackoverflow post that was talking about an issue authenticating to JFrog. In this post was a reference to a script the developer was using to wipe the repo and restore it to fresh state. The script had credentials removed but I noticed a few things. The domain was poorly obfuscated:

`*****.portpequa.lab:8082`

and it was using CLI access to interface with the API, here is a copy of exactly what I saw:

```
RESULTS=`curl https://*****.*********.lab
PATH_TO_FILE=`curl -s -x GET XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX | grep downloadUri `
```
I took a moment to pause and think about what we have here, for one I know the target I am after and two I know there this developer is having trouble authenticating. So I headed over to github and used one of my favorite dorks to see if I can pinpoint the actual script the developer is referencing.

See, I can assume the developer copied and pasted a portion of the script above and took the effort to remove the username and password, so it’s my belief these credentials are hardcoded into the script. All I need now is a little bit of luck and hope that the repo is public.

<img src="/images/CICD_1.png" alt=""> 

There’s the script!

<img src="/images/CICD_2.png" alt=""> 

And there’s our credentials.

Now in our scenario, we get lucky once again. The JFrog instance was externally accessible, a misconfiguration without a doubt.

<img src="/images/CICD_3.png" alt=""> 

And the credentials were valid

<img src="/images/CICD_4.png" alt=""> 

With external access to their Artifactory instance, there are few different things we can do. We can enumerate users to a certain extent. In this scenario, we are not an admin user so we’re hindered by what we can enumerate either through the GUI or JFrog API.

One thing we can do, is deploy packages to these generic-local repository.

## Failure is Part of the Process

Side note about JFrog, it runs on Apache Tomcat, so our payloads will need to be compatible with tomcat. Immediately, we should be thinking about a malicious war file or something along those lines, the next question is how we execute.

There’s two parts to this exploitation chain one is deploying some malicious package that contains our payload to either our C2 of choice or reverse shell handler. The other is getting that payload to execute.

One thing I noticed after reading some of the documentation about Artifactory and Tomcat is that by default Tomcat deploys WAR files written to its application path. So it may be possible to execute our payload by simply deploying this WAR package and visiting it’s URI.

<img src="/images/CICD_5.png" alt=""> 

Artifactory supplies this path for us in the description box of the package. So, let’s compile our payload and see if we can get that initial access.

For the purpose of this lab we will be using good old msfvenom but in the real world, we’ll be using something a bit more stealthy.

<img src="/images/CICD_6.png" alt=""> 

But it turned out my theory was completely wrong. While the packages were getting deployed, I couldn’t execute them. Well, I could but on my local machine but what good is that, right?

<img src="/images/CICD_6.png" alt=""> 

<img src="/images/CICD_7.png" alt=""> 

<img src="/images/CICD_8.png" alt=""> 

So I went back to thinking, this is interesting attack vector is it not? I could deploy ANYTHING I want, download ANYTHING I want but I won’t get code execution unless someone on the local network downloads and executes.

Even more interesting is the fact that I have a way to transfer files from my attack box to the local network, this could be helpful when it comes to exfiltrating data or even to get my tooling over without getting noticed.  At this point I could either phish a user, get local access, download a package from JFrog and get the shell or even better I could download one of the packages on the repository, inject my malicious package and sit back and wait. In this scenario, I could see the repo being used quite often and I could see each time a package was downloaded and so on.

<img src="/images/CICD_8.png" alt=""> 

This type of supply chain attack is super interesting from an adversarial perspective. We essentially have access to multiple pipelines, within the organization’s environment and with a clever enough payload, they would be none the wiser.

So I went ahead and download a script that was hosted on the repo called, update-credentials.sh, this script rotated credentials for service account’s that were also utilizing antifactory within the CI\CD pipeline. The plan would be to infect the current script, wait for the script to be executed and then reupload the clean version.

Now if I am using simple bash reverse shell, the shell will exit once the user realizes it hangs so I added in some extra fluff to let user know to wait while passwords are updated, then once I have the opportunity, I will migrate into a more stable process and the victim would be none the wiser.

<img src="/images/CICD_9.png" alt=""> 

I used msfvenom to generate the bash command for my C2 and just copied and pasted that inside the shell script and re-uploaded the altered script.

Now all I have to do is sit back and wait for the script to be executed.

This type of supply chain attack is dangerous and I’ll cover more about it at the end of this article.

Once the script is executed, I receive the callback to my C2:

<img src="/images/CICD_10.png" alt=""> 

<img src="/images/CICD_11.png" alt=""> 

Also sidenote, these scripts sometimes need to be executed with administrative privileges, hence why our shell comes back as root.

Here I could either migrate processes, create ssh keys, I mean as root the persistence capabilities are endless. But we move on and begin to do some recon around this artifactory environment . There’s a folder called devops and inside that a folder called Ansible with scripts about configuring Ansible and deploying virtual machines for the environment. Inside one of the scripts we find credentials and a URL for the Ansible environment:

<img src="/images/CICD_12.png" alt=""> 

<img src="/images/CICD_13.png" alt=""> 

From here we  can create a SSH tunnel to gain browser access to this Ansible environment, from our artifactory foothold.

<img src="/images/CICD_14.png" alt=""> 

And the creds we decoded work:

<img src="/images/CICD_15.png" alt=""> 

With access now to a different part of the domain, one that’ s available internally we have successfully moved laterally. Our next task is get execution on this underlying  Ansible server in hopes that we can gain shell access and use that to tread even deeper into the domain.

This Ansible tower is a GUI version of the Ansible CLI with some additional tweaks here and there. It’s interesting attack vector  because depending on the access rights of your user, you may have access to a few different things such as certain sets of credentials, if we have the rights on templates we could deploy new machines into the environment and the list goes on and on.

In this particular situation our user just had normal access with administrative or “execute” rights over a particular inventory. The Ansible inventory file defines the hosts and groups of hosts upon which **commands**, modules, and tasks in a playbook operate. Ansible Tower or now known as Ansible Automation Platform allows us the ability to actually execute commands ad hoc on these machines.

Even cooler was that since this is a production environment, we can watch in real time machines being deployed, the security stack being implemented and installed and even what users are being added to the machine. If you find yourself in this situation, it's best to check each one of the resource tabs and understand exactly what you can and can’t do.

If you have execute rights over an inventory, you most likely will have command execution capabilities over certain hosts. Below, I’ll demonstrate how this devops-deploy user had execute rights over the Provision-VM inventory and was able to execute commands on the local host or Ansible server itself.

Here we see the PROVISION-VM inventory:

<img src="/images/CICD_16.png" alt=""> 

And our access over it:

<img src="/images/CICD_17.png" alt=""> 

But remember we were just a regular user, so what’s the harm?

<img src="/images/CICD_18.png" alt=""> 

The issue here is that because of our excessive rights over the inventory file,  we have command execution over hosts under this inventory as this normal user.

<img src="/images/CICD_19.png" alt=""> 

And with that we can simply use the built in shell command to execute our C2 bash one liner:

<img src="/images/CICD_20.png" alt=""> 

The credentials are ready supplied for us, no need for us to know them explicitly:

<img src="/images/CICD_21.png" alt=""> 

And one more thing to mention, these credentials are added to Ansible for this very reason, sometimes you may see root user credentials stored here or even domain administrator credentials. The issue arises once again, that this normal user has access to these sets of credentials.

So let's say there was a service account name AD-INSTALL and it had administrative rights in the domain, the creds could be installed here and given access to this devops-deploy user. Who is keeping track of who has access to this Ansible user because the way I see it, we're pretty much domain admin already if the credentials belong to us and we can use them to execute arbitrary commands.

One last look over before we execute:

<img src="/images/CICD_22.png" alt=""> 

We launch the command and see it’s running:

<img src="/images/CICD_23.png" alt=""> 

Callback in our C2 as the Ansible user on the tower.ansible.lab machine:

<img src="/images/CICD_24.png" alt=""> 

Once again persistence is your decision here along with privilege escalation. But we have successfully gained control over the tower.ansible.lab machine through GUI access to Ansible Tower / Automation Platform.

Luckily again for us, we will find credentials again for a domain user. Now , there is a multitude of different attacks that can be taken here. We are on a domain joined linux machine, we could attempt SSH Hijacking, we can pull krb5ccache tickets, or anything you like. For the sake of lab purposes, lets just say we got creds.

<img src="/images/CICD_25.png" alt=""> 

We then RDP into this machine as a regular domain user and discover quickly that we are a local administrator over our own machine.

In fact there’s a folder called Administrative Tools with a copy of PSExec readily available.

So what can we do now? We’re local admin, we’re remoted into this machine, is anyone else remoted in? Maybe a domain admin? These are questions we can find the answers to quickly with the use built in cmd commands.

First we use **qwinsta** command to identify if anyone else has a remote session active or disconnected on this machine:

<img src="/images/CICD_26.png" alt=""> 

Now that we see there was a disconnected session, we can still hijack this session and gain access to the desktop/console of this Administrator user.

Using PSExec to spawn a SYSTEM shell, we then query user to get the ID needed to hijack the session.

<img src="/images/CICD_27.png" alt="">

Once we have that, we can use tscon to hijack this session and gain access to the Administrator’s console:

<img src="/images/CICD_28.png" alt="">

Luckily for us they left creds once again in plain sight and we use this to own the Domain Controller and subsequently the entire PORTPEQUA domain.

<img src="/images/CICD_29.png" alt="">

So, from an external footprint we discovered credentials that gave us access to Artifactory. We then leveraged that access to attack the supply chain of PORT PEQUA and inject malicious code into a package that was executed by an unsuspecting user. From here we leveraged Ansible Tower access and through the GUI, executed shell commands on the local Ansible host. Here we pivoted and remoted into a windows machine as a local administrator and hijacked a session of a domain administrator for the PORTPEQUA domain.

---
**Some more insight on the supply chain attack in Artifactory:**

For the purpose of the lab, I kept it simple. A bash one liner to a meterpreter C2. We have to remember that Artifactory was a resource to contain ALL the libraries used in whatever packages that are being deployed in the domain. So instead of editing a script, we could edit a python package, something that involved almost no user interaction. Also, we can identify internal python libraries being used and not claimed on pypi.org. The way JFrog is setup is that it was always look for the latest package and pull it down. If the package isn’t claimed on pypi.org, we could create it and host it and sit back and wait. These attacks are very stealthy and quiet and would trigger almost no alarm within the network. So maybe you use a bash one liner or maybe you used a malicious PHP package.

From July of this year:  
[https://jfrog.com/blog/npm-supply-chain-attack-targets-german-based-companies/](https://jfrog.com/blog/npm-supply-chain-attack-targets-german-based-companies/)

Overall the CI/CD pipeline is a very lucrative area of attack for pentester's, red teamer's and adversaries. In these environment's are files upon files loaded with secrets such as plaintext (or easily decoded) passwords, API tokens, AWS keys and more. These environments need to be locked down and secured and heavily monitored for any type of irregular behavior. The Artifactory environment allows for stealthy persistent access whereas the Ansible environment allows for quick, easy lateral movement.
