"use strict"

const dotenv = require("dotenv")
const express = require("express")
const cors = require("cors")
const bodyParser = require("body-parser")
const cookieParser = require("cookie-parser")
const got = require("got")
const { pathExists, readFile } = require("fs-extra")
const { join } = require("path")
const { inspect } = require("util")

dotenv.config()

const pathsFile = join(__dirname, "paths.json")

const prettyError = (error) => {
  if (error instanceof got.HTTPError) {
    let authorization = error.response.request.options.headers.authorization
    if (authorization) {
      const [scheme, token] = authorization.split(" ")
      if (scheme && scheme === "Bearer") {
        error.response.request.options.headers.authorization = `${scheme} redacted`
      } else {
        error.response.request.options.headers.authorization = "redacted"
      }
    }
    console.error(
      inspect(
        {
          request: {
            method: error.response.request.options.method,
            url: error.response.request.options.url.href,
            headers: error.response.request.options.headers,
            json: error.response.request.options.json,
            body: error.response.request.options.body,
          },
          response: {
            statusCode: error.response.statusCode,
            body: error.response.body,
          },
        },
        false,
        4,
        true
      )
    )
  } else {
    console.error(inspect(error, false, 4, true))
  }
}

const ghostStoreClient = got.extend({
  prefixUrl: process.env.GHOST_STORE_PREFIX_URL,
  responseType: "json",
  headers: {
    authorization: `Bearer ${process.env.GHOST_STORE_AUTH_TOKEN}`,
  },
  retry: {
    limit: 2,
  },
})

const app = express()

app.enable("trust proxy")
app.disable("x-powered-by")

app.use(
  cors({
    origin: process.env.GHOST_BASE_URL,
    credentials: true,
  })
)

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf
    },
  })
)

app.use(bodyParser.json())

app.use(bodyParser.urlencoded({ extended: true }))

app.use(cookieParser())

app.get("/:path/*", async (req, res, next) => {
  try {
    const path = req.params.path
    const pathAttributes = paths[path]
    if (pathAttributes && pathAttributes.auth === true) {
      const response = await ghostStoreClient.post("authorize", {
        json: {
          sessionSalt: req.cookies["session-salt"],
          sessionToken: req.cookies["session-token"],
          path: path,
        },
        throwHttpErrors: false,
      })
      if ([400, 401].includes(response.statusCode)) {
        const error = new Error("Invalid authorization")
        console.error(error, req.params, req.cookies)
        return res.status(401).send({
          error: error.message,
        })
      } else if (response.statusCode === 403) {
        const error = new Error("Expired authorization")
        console.error(error, req.params, req.cookies)
        return res.status(403).send({
          error: error.message,
        })
      } else if (response.statusCode !== 200) {
        throw new Error("Could not connect to ghost-store")
      }
    }
    next()
  } catch (error) {
    prettyError(error)
    return res.sendStatus(500)
  }
})

app.get("/authorize", (req, res, next) => {
  if (!req.query.redirect || req.query.redirect === "") {
    const error = new Error("Missing redirect")
    console.error(error, req.query)
    return res.status(400).send({
      error: error.message,
    })
  }
  res.redirect(302, req.query.redirect)
})

app.get("/status", async (req, res) => {
  return res.sendStatus(204)
})

app.use(
  express.static("public", {
    dotfiles: "ignore",
  })
)

var paths

const loadPaths = async () => {
  const exists = await pathExists(pathsFile)
  if (exists === false) {
    paths = {}
    await writeFile(pathsFile, JSON.stringify(paths, null, 2))
  } else {
    const data = await readFile(pathsFile, "utf8")
    paths = JSON.parse(data)
  }
}

const initializeServer = async () => {
  const server = await app.listen(process.env.PORT)
  const serverAddress = server.address()
  if (process.env.DEBUG === "true" && typeof serverAddress === "object") {
    console.info(`Server listening on port ${serverAddress.port}`)
  }
}

const run = async () => {
  try {
    await loadPaths()
    await initializeServer()
  } catch (error) {
    prettyError(error)
    process.exit(1)
  }
}

run()
