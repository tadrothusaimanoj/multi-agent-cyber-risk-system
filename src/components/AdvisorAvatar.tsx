import React from 'react';
import { BotAvatar } from 'bot-avatars';

export default function AdvisorAvatar({ type, size = 36, busy = false }: { type: any, size?: number, busy?: boolean }) {
  return (
    <BotAvatar
      type={type}
      size={size}
      state={busy ? 'working' : 'default'}
      shading="crisp"
    />
  );
}
