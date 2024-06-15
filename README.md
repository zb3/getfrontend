# getfrontend

> [!IMPORTANT]
> This project is in the **experimental** stage.. take the following usefulness claims with a M☉ of salt...

## Why
Let's say we want to scan the frontend code (of a SPA/PWA) for some API keys that shouldn't be exposed to the client (or just explore the whole frontend code), but the app code is split into many chunks with unpredictable names.. and most of these aren't loaded by the browser (you probably only see the login page).. additionally, for each of these chunks, there's a corresponding source map file with the `.map` extension, that happens to not be specified via `sourceMappingURL` (and so the browser doesn't even see it). How do we "get" that frontend?

Well, that's exactly what getfrontend was designed for - to "get" the frontend code, to get all these chunks, to get all these source maps and recreate the original files as accurately as possible.

In theory, this task is not achievable (let me mention the famous "halting problem"), however, in practice, since many apps are bundled with webpack/vite, it's often possible to enumerate all these chunks even with some simple static analysis.
And this is what the program does, it attempts to recognize:
- webpack chunks in various configurations (includes basic federated module support)
- vite chunks
- next.js chunks from a build manifest
- remix chunks from a manifest
- ES6 imports / dynamic imports
- scripts specified in import maps

There's also an "aggressive mode" which - as the name suggests - attempts to find more possible paths (in string literals for example), but this mode isn't "smart" - it's only possible to do a smart detection when the used stack is known.

And of course, there are many false positives, but getfrontend assumes that these are irrelevant - if something is not there, a 404 will be returned and the file won't be saved.

By default JS/CSS files are fetched (and the initial HTML page), but you can specify other extensions if you want them saved. There are shortcuts to specify the most common asset/image/media file extensions.

## What this tool doesn't do
Notably, it:
- doesn't try to unpack minified webpack chunks without source maps
- doesn't crawl html pages, it assumes the specified url points to a SPA
- doesn't do any dynamic analysis to discover chunks
- doesn't attempt to deobfuscate obfuscated (not just minified) JS files
- doesn't even try to defend against any kind of targeted DoS (like infinitely many JS files and so on)

## Basic usage

First you obviously need the target url. If you're trying to run getfrontend for a multipage app with more than one entry, then you need to specify all these entries.
In case you know that a particular url should be included but getfrontend can't find it, you can also specify it on the command line.
```
python getfrontend.py [options]... [root url] [optional additional urls]...
```
Note that only the first url is treated as the "root" url.. practically this means multi-page apps are supported only for the same origin

### Need custom headers? Cookies?
You can specify a custom header to be added to each request using the `--add-header`/`-H` option (works similarly to `curl`).
Additionally there's the `--add-cookie`/`-c` convenience argument to add a cookie. Both options might be used multiple times.
```
python getfrontend.py -H'X-Is-Admin: of-course' -c'is_admin=sure' -c'is_a_bot=nope' https://securesite.com/
```

### Choose the output method
By default everything is **dumped to stdout**.. since this might not necessarily be what you want, you can specify the `--output`/`-o` argument:
```
python getfrontend.py -o /tmp/antarctica_realestate.zip https://realestate.aq/
```
**If it ends with the `.zip` suffix**, then files are written to the specified file as a zip archive, otherwise the argument value is treated as the target directory.

### Choose what you want saved
By default, only JS and CSS files are saved. This is.. a weird default...

If you don't want to save CSS files, the `--no-css`/`-nc` argument is your friend :)

If you want to save more, you can either specify extensions manually using the `--asset-extensions`/`-ae` option (comma-separated or use the argument multiple times), or use these shortcuts:

|Option|Extensions|
| --- | --- |
| `--save-common-assets`/`-sa` | `svg,json,webmanifest,ico,eot,woff,woff2,otf,ttf` |
| `--save-images`/`-si` | `jpg,jpeg,png,gif,webp` |
| `--save-media`/`-sm` | `mp3,ogg,wav,m4a,opus,mp4,mov,mkv,webm` |

### Scripts are being fetched from the wrong path?
While getfrontend attempts to detect the correct "public path" for dynamically loaded chunks, this detection might sometimes yield wrong results, for example when the path is generated in an unusual way.. In that case you might want to supply the path manually.

First, run getfrontend with the `-v` option, then look for strings like "public path for":
```
python getfrontend.py -v https://somesite.com/ |& grep 'public path for'
```
you might see something like this:
```
webpack public path for https://somesite.com/js/main.somehash.js is https://somesite.com/
```
then if you know (for instance by finding it out using devtools) what the actual prefix should be (like `https://somesite.com/js_chunks/`), you can use the `-ppm` option to add the mapping:
```
python getfrontend.py -ppm "https://somesite.com/js/main.somehash.js=https://somesite.com/js_chunks/" https://somesite.com/
```
and then it should work as desired :)


### Chunks/scripts not found?
Try using the aforementioned "aggressive mode" by specifying the `--aggressive-mode`/`-a` option.
It might work.. otherwise - if that's a common configuration - consider filling an issue.


### But there's more..
There are more options, check them out by running:
```
python getfrontend.py --help
```
You can also read the code, albeit be prepared for the worst..
