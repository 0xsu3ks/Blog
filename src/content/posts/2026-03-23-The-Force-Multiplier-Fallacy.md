---
title: "The Force Multiplier Fallacy"
date: 2026-03-23
tags: [posts]
excerpt: "My Thoughts on AI in 2026"
---

# The Force Multiplier Fallacy: AI Isn't Replacing You, Your Lack of Foundation Is

It's 4am and I just fed the newest addition to the family. As I'm holding him I think about what his life and my oldest son's life will look like in the future. Will they like breaking things like me? My first son already shows promise, he wants to know the *why* to everything. Why does this do that? How does it work? It's an exciting time as a parent to watch his mind working like that, but it's also a scary time when we consider where we are in the world today with technology and AI.

How much of AI will influence the way he thinks and processes information? How much of it will shape the way he learns or doesn't learn? These tools we've already become so reliant on are causing us to move faster than ever before in software development, in research, in decision-making, in everything. But at what cost?

We're in an era of de-skilling and most people don't even realize it's happening. We're trading depth for speed and calling it progress.

Which is why when it comes to writing something like this, I want to make sure I capture *me* and only me. Not a prompt output polished into something that sounds like every other thought leadership post on LinkedIn. My words. My thinking. My voice. If that means it takes longer than two minutes to write, so be it.

## Before and After

I remember what it was like before all this. You had a problem, you went and figured it out. You Googled it, sure, but you read the man page. You read the source. You broke things and fixed them and in the process you built an intuition that no shortcut could replicate. When I was coming up in offensive security, the learning *was* the struggling. The struggling was the point.

Now? I can ask a model to write me a Python script and it'll hand me something functional in seconds. And I'll be honest, my Python skills have suffered  greatly because of it. I'm not writing the same volume of code by hand that I used to. That's a real trade-off and I'm not going to pretend it isn't.

But here's the thing, I still know *what* to ask for. I still know when the output is wrong. I still know why a particular approach is flawed. The knowledge is still there, I'm just not exercising the muscle as often. And that distinction matters, because I think a lot of people are skipping the part where you build the knowledge in the first place and going straight to the shortcut. That's where de-skilling becomes dangerous.

## The Two-Sided Problem

As it stands, this space feels very binary. You're either "For AI" or "Anti AI", and I think that's a dangerous precedent.

In some of my circles, people think I'm the enemy because I love what AI is doing. I use it constantly, local models for offensive research, Claude and GPT for development work, agentic tooling to move faster on projects. I'm not shy about it. I think these tools are genuinely transformative and I'd be stupid not to use them.

In other circles, people think I'm a skeptic because I ask to slow down (just a little). Because I push back when someone wants to onboard an LLM into a workflow without thinking through the effects it might have on quality of work, *on team morale*, on the people who now feel like they're being replaced by a chatbot that hallucinates 15% of the time.

Both reactions are wrong. The reality is messier than either camp wants to admit.

I embrace AI while understanding its limitations, not only from an accuracy and precision perspective, but from a governance one. Every piece of data shared with these models could be used to train future versions. Where does that leave client confidentiality? Where does that leave proprietary code, internal strategies, sensitive findings? Most organizations haven't even begun to think about this seriously, and the ones that have are mostly writing policies that nobody reads or enforces.

## The Human Is Still Driving

Here's what I keep coming back to when people ask me if AI is going to replace pentesters or developers or whatever the panic of the week is. In every scenario where I use AI effectively, I'm the one driving.

I'm the one making the connection between a reverse proxy misconfiguration and a path to local file inclusion. I'm the one who looks at an application's architecture and thinks "that trust boundary is in the wrong place." Sure, maybe the LLM helped me get there faster, helped me draft the exploit, saved me from Googling the same curl syntax for the thousandth time. But I honestly don't know if it could make that lateral connection or that intuitive leap just yet without my human experience guiding it.

The model is a force multiplier. It is not the force.

The people who understand this distinction are going to do incredibly well in the next few years. The people who treat it as a replacement for thinking are going to produce work that looks competent on the surface and falls apart under any real scrutiny.

## The Cost of Superpowers

The other interesting aspect that comes up in all my circles is cost. Right now, pick your model, pick your vendor, it runs you somewhere between twenty and a hundred bucks a month to feel like you have superpowers. You sit there and watch the predictive superhero generate lines and lines and lines of code. Some good. Some bad. Opus, GPT, Sonnet, doesn't matter. Each has its issues.

But then again, maybe it just comes back to the person prompting? It certainly can't be the context window or the token limits preventing you from building the world's next great SaaS, can it?

Sure I'm being a little facetious, but the point is real. Some of the bugs I've seen in AI-generated code are so subtle they would absolutely wreck an application down the line. Not the obvious stuff, not syntax errors or missing imports. The kind of logic bugs that pass code review, pass tests, and then blow up six months later when edge cases start hitting production. The kind of bugs that would require a senior developer to even identify, let alone fix.

And yet, and this is the tension, it's also made going to market with an idea dramatically faster. I'm building multiple iOS apps right now and the velocity is genuinely remarkable compared to what it would have been three years ago. There is real beauty in these tools for software development. You just have to know where the beauty ends and where the liability begins.

## The News Cycle Doesn't Help

You won't have to look far in the news to find stories about AI causing problems for businesses. A service goes down because of some AI-assisted code that got pushed without proper review. A chatbot tells a customer something wildly wrong and it makes the rounds on social media. An automated system makes a decision that a human would have immediately flagged as insane.

On the flip side, you'll also find stories about AI being used to help cure a dog's cancer, accelerate drug discovery, identify patterns in medical imaging that humans missed. The media is going wild with all of it because these stories sell. the bad and good alike.

But here's what I truly believe, we're in the next generation of technology. This isn't a fad. This isn't some crypto NFT. This is a fundamental shift in how work gets done. And the people and companies who view AI as a means, a helper, a tool, a force multiplier, rather than a replacement for human judgment will find themselves at the top of the totem pole in a few years. The ones who go all-in on replacement, who gut their teams and hand the keys to the model, are going to learn some expensive lessons.

## Offensive Security and the AI Hype

I have to talk about this because it's my world and the discourse is getting ridiculous.

All these "pentest AGI agents" that are popping up? To me they're mostly silly. And I see people in comment sections saying things like "this just proves that pentests follow the same runbook every time." To which I say...yeah? You didn't know this? A structured methodology isn't a weakness. It's literally the point. The value of a pentest was never in the novelty of running Nmap. It was in the human interpreting the results and making connections that a checklist can't.

For red teams, I chuckle a bit more. X is always getting spicy about red teaming and I genuinely enjoy watching the greats talk about how they use LLMs in their workflows. It inspires me and it's influenced my own local setup for fuzzing and research. But I'm not sold on the "LLM red teaming" pitch, hold on while I just social engineered this user with some novel pretext only to get caught installing a Docker container to run SQLMap. The creativity in red teaming comes from the operator, not the model. Always has. Always will.

Where I do see real value in offensive AI is in collaboration, faster recon, better pattern matching across large data sets, drafting reports, generating phishing pretexts that I then refine. The boring stuff, the volume stuff, the stuff where speed matters more than nuance. That's where these tools shine in this field.

## The Misinformation Problem

Here's another thing that genuinely concerns me. The amount of information available right now is staggering and it's increasingly clouded by misinformation. Not just in the news or on social media. In technical content too. AI-generated blog posts, AI-generated tutorials, AI-generated Stack Overflow answers that are confidently wrong. The signal-to-noise ratio is deteriorating fast.

For experienced practitioners, this is annoying but manageable. You can spot the hallucinated nonsense because you have the foundation to check it against.

For people trying to break into the field? It's genuinely scary. They don't have that filter yet. They're reading an AI-generated tutorial about web application security that looks polished and authoritative and contains a subtle fundamental error that will shape their understanding of the topic going forward. They don't know what they don't know, and the tools that are supposed to help them learn are sometimes teaching them wrong.

I think this will be the direct cause of people getting left behind, not because AI replaces them, but because the noise prevents them from ever building the real foundational skills in the first place.

## What's Coming Next

As for attacking these systems, the LLMs themselves, the RAG pipelines, the agentic architectures, I'm working on another post for that. But one thing I've noticed is that under the hood, it's sort of the same ballgame for threat actors, red teamers, and pentesters, and that's the interesting part. As companies onboard all this new technology without thinking through the security implications, threat actors are waiting patiently to strike with simple, effective, and downright destructive attacks that can propagate to production code and eventually to market.

The trust boundaries are drawn wrong. The tooling isn't mature. The governance is an afterthought. If you're in offensive security, this should be the most exciting time in your career because the attack surface is expanding faster than the defenses can keep up.

## The Advice I'd Give

Don't sleep on this stuff. It's not going anywhere.

Learn to use it. Be smart with it. Understand what it's good at and where it falls apart. Set yourself apart by being the person who can leverage AI and explain why its output is wrong when it's wrong.

And for those who are looking to break into the field, whether that's offensive security, software development, or anything technical, I strongly advise learning the hard way first. The manual way. Read the documentation. Write the code by hand. Struggle with the debugger. Build the muscle memory and the intuition that comes from doing things the long way.

Because it will only make you better and more powerful when you combine it with good AI tooling later. The shortcut is only a shortcut if you know the long road it's cutting across. Otherwise it's just a path to a destination you don't actually understand.

The people who will thrive in this next era aren't the ones who use AI the most or the least. They're the ones who built the foundation first and know exactly what the tool is doing for them and what it isn't.
