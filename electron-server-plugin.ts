// packages/core/src/server/better-auth/electronPlugin.ts
import 'dotenv/config'
import { createHash, createHmac } from 'node:crypto'
import process from 'node:process'
import type { ZodAuthListUserWithRole } from '@big-product/packages-core/server/db/schema/AuthSchema/authTables'
import {
  session,
  user,
} from '@big-product/packages-core/server/db/schema/AuthSchema/authTables'
import type { Prettify } from '@big-product/packages-utils/typescript-lib'
import type { BetterAuthPlugin, JWTPayload } from 'better-auth'
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getAccessToken,
  getSessionFromCtx,
  sessionMiddleware,
} from 'better-auth/api'

import { sign, verify } from 'hono/jwt'
import { z } from 'zod'

// Move regex to top-level scope for performance
const SESSION_TOKEN_REGEX = /session_token=([^;]+)/

// [配置] 這是用於簽名 Ticket 的密鑰，必須保密！
// 建議和 BETTER_AUTH_SECRET 分開，或者使用其派生密鑰
const TICKET_SECRET = process.env.BETTER_AUTH_SECRET || 'CHANGE_ME_IN_PROD'
type JWT = {
  userid: string
  exp: number
  jti: string
}
export const electronServerPlugin = (
  options:
    | {
        method: 'extenal' | 'internal'
      }
    | undefined,
) => {
  return {
    id: 'electron-bridge',

    hooks: {
      before: [
        {
          matcher: (context) => context.path.includes('/get-session'),
          handler: createAuthMiddleware(async (ctx) => {
            console.log('\n👇👇👇 --- [Server] 收到請求監控 --- 👇👇👇')
            if (ctx.request) {
              console.log(`📡 URL: ${ctx.request.url}`)
              console.log(`Pm Method: ${ctx.request.method}`)
            } else {
              console.log('📡 URL: <no request>')
              console.log('Pm Method: <no request>')
            }

            // 1. 🔥 檢查 Origin (確認是否偽造成功)
            const origin = ctx.headers?.get('origin')
            console.log(`🏠 Origin: ${origin || '❌ 無 Origin'}`)

            // 2. 🔥 檢查 Cookie (這是最重要的！)
            const cookie = ctx.headers?.get('cookie')
            if (cookie) {
              console.log('🍪 Cookie Header:', cookie)
              if (cookie.includes('BiG-React-Monorepo.session_token')) {
                console.log('✅ 發現目標 Token！')
              } else {
                console.log('⚠️ 有 Cookie 但沒發現目標 Token')
              }
            } else {
              console.error('❌ Cookie Header 是空的！Electron 沒帶過來！')
            }

            // 3. 打印所有 Headers (排查是否有大小寫問題，比如 cookie vs Cookie)
            // 注意：ctx.headers 通常是標準 Headers 對象，需要轉一下才能打印全
            const allHeaders: Record<string, string> = {}
            if (ctx.headers) {
              ctx.headers.forEach((v, k) => {
                allHeaders[k] = v
              })
            }
            console.log('📜 完整 Headers:', allHeaders)

            console.log('👆👆👆 -------------------------------- 👆👆👆\n')

            // 必須返回 context 讓請求繼續，否則請求會在這裡卡死
            return {
              context: ctx,
            }
          }),
        },
      ],
      // after hook 其實是for response的，不能拿到user和session，只能通過setcookie裡面的token去拿,context只有response header
      after: [
        {
          matcher: (context) => context.path.includes('/electron/exchange'),
          handler: createAuthMiddleware(async (ctx) => {
            console.log(
              '\n📦 📦 📦 [Server] 響應發送前檢查 (Response) 📦 📦 📦',
            )
            if (!ctx.headers) {
              throw new APIError('BAD_REQUEST')
            }
            // 🔥 1. 這是最終要發給客戶端的 Response 對象
            // const response = ctx.responseHeaders

            // if (!response) {
            //   console.error(
            //     '❌ [致命錯誤] ctx.response 是 undefined！請求可能還沒處理完？',
            //   )
            //   return
            // }
            // 這裡的 ctx.response 是最終要發出去的響應對象
            // 檢查 Set-Cookie 頭
            const header = ctx.context.responseHeaders

            if (header) {
              const cookie = header.get('set-cookie')
              if (cookie) {
                console.log('🍪 [Set-Cookie 生成成功!]')
                // Set-Cookie 可能是一個長字符串，也可能是數組，我們拆開看
                // 注意：在某些環境下 get 只返回第一個，但日誌通常能看到
                console.log(cookie)
                if (cookie.includes('domain=localhost')) {
                  console.log('✅ Domain 屬性正確: localhost')
                } else {
                  console.error(
                    '❌ 警告: 缺少 Domain=localhost，持久化會失敗！',
                  )
                }
              } else {
                console.error('❌ 警告: [Set-Cookie 生成失敗!！！！！]')
              }
            } else {
              console.error(
                '❌ [致命錯誤] 響應頭裡沒有 Set-Cookie！setNewSession 沒生效！',
              )
            }
            console.log(
              '📦 📦 📦 ----------------------------------- 📦 📦 📦\n',
            )

            // return {
            //   response: ctx.response,
            // }
          }),
        },
        {
          /**
           * [Step 1: 攔截器 (The Gatekeeper)]
           * 這是數據流的第一道關卡。
           * 場景：GitHub 剛剛重定向回 Hono，Better-Auth 已經處理完登錄邏輯。
           *
           * 判斷依據：看看請求的url（path）裡面有沒有callback，如果有，證明是oauth最後一步，github回調到auth api的
           * 注意：這裡依然是server端代碼
           */
          matcher: (context) => {
            type Context = Prettify<typeof context>
            // context.query 是 URL 查詢參數對象
            const path = context.path as string | undefined
            // 如果包含暗號，返回 true，表示「這個請求歸我管，我要執行 handler」
            console.log('path', path)
            if (path) {
              return path.startsWith('/callback')
            }
            return false
          },

          /**
           * [Step 2: 處理器 (The Handler)]
           * 只有通過 matcher 的請求才會進入這裡。
           * 這裡發生了「偷天換日」：
           * 原本 Better-Auth 打算把用戶重定向去 "/desktop-handoff" (HTTP)，
           * 我們在這裡攔截，改為重定向去 "bigxu://" (Custom Protocol)。
           */
          handler: createAuthMiddleware(async (ctx) => {
            type Context = Prettify<typeof ctx>
            // [Data Flow] 從上下文獲取剛生成的 Session
            // 拿不到的，這裡上下文只有response的header
            // const sessionAfter = ctx.context.session
            // const userAfter = ctx.context.user as ZodAuthListUserWithRole | null
            // console.log('session', sessionAfter)
            // console.log('user', userAfter)

            // 這裡拿到response header，這個response其實並沒有發出去，這個動作是發之前的
            const headers = ctx.context.responseHeaders

            // 從header拿到location，其實就是拿跳轉的參數scheme，這個location其實就是authClient.signin裡面的callback
            const location = headers?.get('location')

            // 拿到setCookie，要拿到裡面的session-token
            const setCookieHeader = headers?.get('set-cookie')

            // 檢查如果沒有這兩個參數就直接退出+跳轉
            if (
              !(
                location?.includes('/electron-handoff?scheme=') &&
                setCookieHeader
              )
            ) {
              console.log('setCookieHeader and location not found')
              return ctx.redirect(`http://localhost:3001/better-auth`)
            }

            // 先拿scheme，最後redirect劫持重定向到Electron用
            const targetUrl = new URL(location, 'http://localhost')
            const scheme = targetUrl.searchParams.get('scheme') || 'bigxu'

            // 處理session token
            const tokenMatch = setCookieHeader.match(SESSION_TOKEN_REGEX)
            if (!tokenMatch) {
              console.log('tokenMatch not found')
              return ctx.redirect(`http://localhost:3001/better-auth`)
            }
            const rawToken = decodeURIComponent(tokenMatch[1]).split('.')[0]
            //  這裡拿不到context裡面的session，因為是after hook，只能拿到Github的callback，裡面有setCookie
            // const contextSession = await getSessionFromCtx(ctx)

            // 拿著sessionToken去query user
            const sessionToken =
              await ctx.context.internalAdapter.findSession(rawToken)

            // 安全防禦：如果登錄失敗或沒有 Session，直接放行（讓它報錯或去默認頁面）
            if (!sessionToken) {
              console.log('User Session not found')
              return ctx.redirect(`http://localhost:3001/better-auth`)
            }

            // [Step 2.2: 簽發 Ticket (The Token)]
            // 這是我們設計的「信使」。
            // 內容：只包含用戶 ID。
            // 有效期：60秒 (越短越安全，防止攔截重放)。
            // 簽名：使用後端密鑰簽名，前端無法偽造。
            const ticket = await sign(
              {
                userid: sessionToken.user.id,
                exp: Math.floor(Date.now() / 1000) + 60,
                jti: crypto.randomUUID(), // [Security] 唯一ID，可用於防止重放攻擊
              } as JWT,
              TICKET_SECRET,
            )
            console.log(`ticket: ${ticket}`)
            /**
             * [Step 3: 變軌 (The Switch)]
             * 這一步是改變location，也就是改變redirect的方向，然後把response發出去
             * 瀏覽器收到這個 redirect 指令後：
             * 1. 發現是 bigxu:// 協議。
             * 2. 操作系統介入。
             * 3. 喚醒 Electron 應用。
             * 4. 將 ticket 作為參數傳遞給 Electron。
             * 注意：這裡沒有傳遞 Cookie！Cookie 留在了瀏覽器裡。
             * Ticket 是唯一跨越這條「斷橋」的信息。
             */
            // return ctx.redirect(`http://localhost:3001/better-auth`)
            return ctx.redirect(`${scheme}://auth-callback?ticket=${ticket}`)
          }),
        },
      ],
    },

    // [Step 4: 兌換處 (The Exchange)]
    // 這部分雖然不在 hook 裡，但必須寫在同一個插件裡。
    // Electron 拿到 Ticket 後，會回頭調用這個接口來換取真正的 Session。

    endpoints: {
      exchangeTicket: createAuthEndpoint(
        '/electron/exchange',
        {
          method: 'POST',
          body: z.object({
            ticket: z.string(),
          }),
          // 這裡會攔截請求是否合規！！！！因為electron這次請求並沒有cookie，是來兌換jwt的
          // use: [
          //   sessionMiddleware,
          // ],
        },
        async (ctx) => {
          try {
            if (ctx.request === undefined) {
              throw new APIError('BAD_REQUEST')
            }
            // if (ua === null) {
            //   throw new APIError('BAD_REQUEST')
            // }
            // A. 驗證簽名：確保是我們剛才簽發的，且沒過期
            let payload: JWT | undefined
            try {
              payload = (await verify(
                ctx.body.ticket,
                TICKET_SECRET,
              )) as JWTPayload as JWT
              console.log('payload', payload)
            } catch (e: unknown) {
              if (e && e instanceof Error) {
                console.log(e.message)
                throw new Error(e.message)
              }
            }
            if (!payload) {
              return
            }
            const userQuery = (await ctx.context.internalAdapter.findUserById(
              payload.userid,
            )) as ZodAuthListUserWithRole | null
            if (!userQuery) {
              console.error('User not found')
              throw new APIError('UNAUTHORIZED', {
                message: 'User not found',
              })
            }
            console.log(userQuery)
            // [配置] Electron 專屬有效期 (比如 30 天，比瀏覽器長)
            const now = new Date()
            const electronExpiresAt = new Date(
              now.getTime() + 31 * 24 * 60 * 60 * 1000,
            )
            // B. 創建 Session：這是 Electron 自己的 Session，與瀏覽器無關

            const sessionForElectron =
              await ctx.context.internalAdapter.createSession(
                userQuery.id,
                false,
                {
                  userAgent:
                    ctx.request.headers.get('user-agent') || 'Electron App',
                  ipAddress:
                    ctx.request.headers.get('x-forwarded-for') || '127.0.0.1',
                  expiresAt: electronExpiresAt, // 強制覆蓋過期時間
                },
              )

            // [Fix 1] 🔥 核心修復：手動設置 HTTP Cookie 頭！
            // internalAdapter 不會碰 HTTP 頭，我們必須自己來。
            // 我們使用 Better-Auth 上下文裡的 Cookie 配置來確保名字和屬性正確。
            // 假設 sessionToken 配置在 authCookies 裡 (Better-Auth 默認行為)
            const tokenConfig = ctx.context.authCookies.sessionToken
            const dataConfig = ctx.context.authCookies.sessionData // JWT 配置

            await ctx.setSignedCookie(
              tokenConfig.name,
              sessionForElectron.token,
              ctx.context.secret,
              {
                ...tokenConfig.options,
                httpOnly: true,
                domain: 'localhost',
                sameSite: 'none',
                secure: true, // 本地 localhost 調試時必須是 false，否則 cookie 寫不進去！
                path: '/',
                maxAge: 60 * 60 * 24 * 31, // 31天
              },
            ) // 3. 🔥 [第二槍] 手動設置 Session Data (修正版)
            // 修正點：使用 setCookie (不帶簽名)，因為前端解不開簽名！
            const signature = createHmac('sha256', ctx.context.secret)
              .update(sessionForElectron.token)
              .digest('base64')
              .replace(/\+/g, '-') // Base64URL 替換
              .replace(/\//g, '_')
              .replace(/=+$/, '')

            const sessionDataPayload = JSON.stringify({
              session: {
                session: sessionForElectron,
                user: userQuery,
                updatedAt: new Date(sessionForElectron.updatedAt).getTime(),
                version: '1',
              },
              expiresAt: new Date(sessionForElectron.expiresAt).getTime(),
              signature: signature,
            })

            // 使用 Base64URL 格式 (前端友好)
            const base64SessionData = Buffer.from(sessionDataPayload)
              .toString('base64')
              .replace(/\+/g, '-')
              .replace(/\//g, '_')
              .replace(/=+$/, '')

            // if (dataConfig) {
            //   // 🔥 注意：這裡改用 ctx.setCookie (Raw Cookie)
            //   // 這樣就不會加上那個該死的 ".簽名" 後綴了
            //   ctx.setCookie(dataConfig.name, base64SessionData, {
            //     ...dataConfig.options,
            //     httpOnly: false, // 🔥 必須是 false，前端才能讀到！
            //     sameSite: 'none',
            //     secure: true,
            //     path: '/',
            //     domain: 'localhost', // 持久化
            //     maxAge: 60 * 60 * 24 * 30,
            //   })
            // }
            console.log('🛠️ [Endpoint] 手動 Cookie 注入完成，準備發貨...')
            // ctx.context.setNewSession({
            //   session: sessionForElectron,
            //   user: userQuery,
            // })

            // C. 返回結果：Better-Auth 會自動處理 Set-Cookie Header
            return ctx.json({
              session: sessionForElectron,
              user: userQuery,
              // cookie: cookie,
            })
          } catch (e) {
            // 錯誤處理優化
            const message = e instanceof Error ? e.message : '無效或過期的票據'
            throw new APIError('UNAUTHORIZED', {
              message: message,
            })
          }
        },
      ),
      fastTicket: createAuthEndpoint(
        '/electron/fastTicket',
        {
          method: 'POST',
          requireHeaders: true,
          // 這個端點應該是瀏覽器發起的，所以一定要包含session
          use: [
            sessionMiddleware,
          ],
        },
        async (ctx) => {
          try {
            if (ctx.request === undefined) {
              throw new APIError('BAD_REQUEST')
            }
            // if (ua === null) {
            //   throw new APIError('BAD_REQUEST')
            // }
            // A. 驗證簽名：確保是我們剛才簽發的，且沒過期
            const fastTicketSession = ctx.context.session
            if (fastTicketSession === null) {
              throw new APIError('BAD_REQUEST')
            }
            console.log('FastTicket')
            // [配置] Electron 專屬有效期 (比如 30 天，比瀏覽器長)
            const ticket = await sign(
              {
                userid: fastTicketSession.user.id,
                exp: Math.floor(Date.now() / 1000) + 60,
                jti: crypto.randomUUID(), // [Security] 唯一ID，可用於防止重放攻擊
              } as JWT,
              TICKET_SECRET,
            )
            console.log(`ticket: ${ticket}`)
            /**
             * [Step 3: 變軌 (The Switch)]
             * 這一步是改變location，也就是改變redirect的方向，然後把response發出去
             * 瀏覽器收到這個 redirect 指令後：
             * 1. 發現是 bigxu:// 協議。
             * 2. 操作系統介入。
             * 3. 喚醒 Electron 應用。
             * 4. 將 ticket 作為參數傳遞給 Electron。
             * 注意：這裡沒有傳遞 Cookie！Cookie 留在了瀏覽器裡。
             * Ticket 是唯一跨越這條「斷橋」的信息。
             */
            // return ctx.redirect(`http://localhost:3001/better-auth`)
            // return ctx.json({
            //   success: true,
            //   ticket: ticket,
            //   // 告訴前端："拿到數據後，請跳去這裡"
            //   redirect_url: `bigxu://auth-callback?ticket=${ticket}`,
            // })
            return {
              ticket: ticket,
            }
            // return ctx.redirect(`bigxu://auth-callback?ticket=${ticket}`)
          } catch (e) {
            // 錯誤處理優化
            const message = e instanceof Error ? e.message : '未知錯誤'
            throw new APIError('UNAUTHORIZED', {
              message: message,
            })
          }
        },
      ),
    },
  } satisfies BetterAuthPlugin // 強制類型檢查，確保符合規範
}
