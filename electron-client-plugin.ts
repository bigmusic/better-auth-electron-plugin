// packages/core/client/better-auth/electron-client-plugin.ts

import type { BetterFetchOption } from '@better-fetch/fetch'
import { isElectronWindow } from '@big-product/packages-core/client/is-electron-window'
import type { Prettify } from '@big-product/packages-utils/typescript-lib'
import type { BetterAuthClientPlugin } from 'better-auth/client'
import { id } from 'effect/Fiber'
import { context } from 'effect/Sink'

export const electronClientPlugin = () => {
  return {
    id: 'electron-plugin',
    // $InferServerPlugin: {} as ReturnType<typeof myPlugin>,
    // 這裡用getActions方法其實為了client實例初始化的時候，跑一次函式，讓兩個event listener得以註冊，至於返回什麼並不重要
    // $store 裡面的notify其實只是一個「信號彈」。它告訴所有的組件（比如 useSession）：「嘿！數據可能過期了，你們自己去服務器重新拉取一下吧！」手握這個 $store，就等於掌握了讓整個 App 「強制刷新狀態」 的遙控器。
    // type $store ={
    //     notify: (signal: string) => void;
    //     listen: (signal: string, listener: () => void) => void;
    //     atoms: Record<string, WritableAtom<any>>;
    // }
    getActions: function ($fetch, $store, options) {
      if (!isElectronWindow(window)) {
        return {}
      }
      // if (typeof window === 'undefined' || !window.electron) {
      //   return {}
      // }

      // 監聽窗口聚焦
      window.addEventListener('focus', () => {
        // 告訴 Better-Auth: "醒醒，檢查一下 Session 過期沒"
        // $sessionSignal 是內部信號，觸發 useSession 重新 fetch
        console.log('focus')
        $store.notify('$sessionSignal')
      })
      // 1. 掛載監聽
      // 注意：window.electron 是 electron-vite 模板預設暴露的
      // 2. 核心邏輯：監聽 Deep Link (替代 Expo 的 Linking)
      window.electron.ipcRenderer.on(
        'deep-link-received',
        async (_event, deepLinkUrl) => {
          console.log('[Electron] 收到 Ticket，開始兌換...')
          if (typeof deepLinkUrl !== 'string') {
            return
          }
          const urlObj = new URL(deepLinkUrl)
          console.log('urlObj', urlObj)
          // 🛡️ 防禦層 1: 協議檢查 (雖然 OS 通常只會轉發對的，但防禦編程不嫌多)
          // 注意：urlObj.protocol 包含冒號
          if (urlObj.protocol !== 'bigxu:') {
            console.warn('[Electron Plugin] 忽略非本協議鏈接:', urlObj.protocol)
            return
          }
          // 🛡️ 防禦層 2: 路由檢查 (Action Check)
          // 識別 auth-callback 這個動作
          // toLowerCase() 是為了容錯，防止手滑寫成 Auth-Callback
          const action = urlObj.hostname.toLowerCase()

          if (action !== 'auth-callback') {
            console.warn(`[Electron Plugin] 未知動作: ${action}，忽略處理`)
            // 如果未來有 bigxu://settings，可以在這裡加 else if
            return
          }
          // --- 通過安檢，開始業務邏輯 ---
          const ticket = urlObj.searchParams.get('ticket')
          if (!ticket) {
            console.error('[Electron Plugin] 無效鏈接：找不到 ticket 參數')
            return
          }
          console.log('ticket', ticket)
          try {
            // 發送兌換請求
            // 注意：這裡不需要手動管理 Cookie！
            // Chromium 會自動處理 Set-Cookie 頭
            const result = await $fetch('/electron/exchange', {
              method: 'POST',
              body: {
                ticket: ticket,
              },
            })

            // 兌換成功，強制刷新狀態
            // 強制瀏覽器重新導航到當前 URL
            // window.location.reload()
            $store.notify('$sessionSignal')

            // 為了確保 HttpOnly Cookie 絕對生效，有時 reload 是最穩的
            // window.location.reload();
          } catch (e) {
            console.error('[Electron] 兌換失敗', e)
          }
        },
      )

      return {}
    },
    // fetchPlugins: [
    //   {
    //     id: 'electron-plugin',
    //     name: 'electron-plugin',
    //     hooks: {
    //       onRequest: async function (requestCTX) {
    //         if (!isElectronWindow(window)) {
    //           return requestCTX
    //         }

    //         if (requestCTX.url.toString().includes('/sign-in/social')) {
    //           console.log(
    //             '[Electron Plugin] 攔截到社交登錄請求，正在注入參數...',
    //           )

    //           // 解析當前的 body (因為它是 JSON 字符串)
    //           const body = JSON.parse((requestCTX.body as string) || '{}')

    //           // 🔥 強制注入 redirect: false
    //           // 這樣 Better Auth 就不會自動跳轉，而是返回 { url: ... }
    //           body.redirect = false

    //           // 🔥 自動替換 callbackURL 為 Deep Link
    //           // 這樣 UI 層連 callbackURL 都不用傳，全自動！
    //           body.callbackURL = 'bigxu://auth-callback'

    //           // 把修改後的 body 塞回去
    //           requestCTX.body = JSON.stringify(body)
    //         }
    //         return requestCTX
    //       },
    //     },
    //   },
    // ],
  } satisfies BetterAuthClientPlugin
}
