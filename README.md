# Google sing-in

This is an example of how to create a web with google sing in

Is based on [Google sign in with Go](https://skarlso.github.io/2016/06/12/google-signin-with-go/) with some improvements.

Use GIN framework
Tkanos/Config
golang.org/x/oauth2/google

I build this using go mod and golang 1.13 on my mac.

You can build by running

```bash
go build
```

We need to define the environment vars

- CLIENT_ID
- CLIENT_SECRET
- REDIRECT_URL

This parameters should be defined on [Dev Console](https://console.developers.google.com/)

Optionally we can create a bash file to add this vars

```bash
#! /bin/bash
CLIENT_SECRET= CLIENT_ID= REDIRECT_URL=  ./google-sing-in

```
