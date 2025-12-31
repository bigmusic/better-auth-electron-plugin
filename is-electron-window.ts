import type { Prettify } from '@big-product/packages-utils/typescript-lib'

type Process = {
  readonly platform: string
  readonly versions: {
    [key: string]: string | undefined
  }
  readonly env: {
    [key: string]: string | undefined
  }
}

type WebFrame = {
  insertCSS: (css: string) => string
  setZoomFactor: (factor: number) => void
  setZoomLevel: (level: number) => void
}

type WebUtils = {
  getPathForFile: (file: File) => string
}
type IpcRendererEvent = {
  ports: MessagePort[]
  sender: IpcRenderer
  preventDefault: () => void
  readonly defaultPrevented: boolean
}
type IpcRendererListener = (event: IpcRendererEvent, ...args: unknown[]) => void
type IpcRenderer = {
  /**
   * 監聽通道消息
   * @param channel 消息通道名稱
   * @param listener 回調函數
   */
  on: (channel: string, listener: IpcRendererListener) => () => void
  once: (channel: string, listener: IpcRendererListener) => () => void
  removeAllListeners: (channel: string) => void
  removeListener: (
    channel: string,
    listener: (...args: unknown[]) => void,
  ) => IpcRenderer
  send: (channel: string, ...args: unknown[]) => void
  invoke: (channel: string, ...args: unknown[]) => Promise<unknown>
  postMessage: (
    channel: string,
    message: unknown,
    transfer?: MessagePort[],
  ) => void
  sendSync: (channel: string, ...args: unknown[]) => unknown
  sendTo: (webContentsId: number, channel: string, ...args: unknown[]) => void
  sendToHost: (channel: string, ...args: unknown[]) => void
}

// declare global {
//   interface Window {
//     electron: {
//       ipcRenderer: IpcRenderer
//     }
//   }
// }
type ElectronWindow = Window & {
  electron: {
    thisIsInSidePackages: 'this is inside package'
    webUtils: Prettify<WebUtils>
    webFrame: Prettify<WebFrame>
    process: Prettify<Process>
    ipcRenderer: Prettify<IpcRenderer>
  }
}

// 🔥 核心：自定義類型守衛函數
// 語法含義：如果返回 true，則參數 win 的類型被「鎖定」為 ElectronWindow
export function isElectronWindow(
  win: Window | typeof globalThis,
): win is ElectronWindow {
  return (
    typeof win !== 'undefined' &&
    'electron' in win &&
    typeof win.electron !== 'undefined'
  )
}
