type ListenHandler = (e: { payload: unknown }) => void;

const handlers = new Map<string, ListenHandler>();

export const tauriListenBridge = {
  register(channel: string, handler: ListenHandler) {
    handlers.set(channel, handler);
  },
  unregister(channel: string) {
    handlers.delete(channel);
  },
  emit<T>(channel: string, payload: T) {
    handlers.get(channel)?.({ payload });
  },
  reset() {
    handlers.clear();
  },
};
