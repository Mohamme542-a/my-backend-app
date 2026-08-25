/* Archive native audio bridge: Android background playback + media notification. */
(function () {
  const cap = window.Capacitor;
  const nativeAudio = cap?.Plugins?.NativeAudio;
  const playback = cap?.Plugins?.ArchivePlayback;
  const isNative = !!(cap?.isNativePlatform?.() && nativeAudio && playback);
  let configured = false;
  let assetId = '';
  let completeHandle;
  let stateHandle;
  let onComplete = null;
  let onState = null;

  async function configure() {
    if (!isNative) return false;
    if (!configured) {
      await nativeAudio.configure({ backgroundPlayback: true, showNotification: true, focus: true });
      try { await playback.requestNotifications(); } catch (e) { console.warn('notifications', e); }
      if (!completeHandle) {
        completeHandle = await nativeAudio.addListener('complete', event => {
          if (!assetId || !event?.assetId || event.assetId === assetId) onComplete?.();
        });
      }
      if (!stateHandle) {
        stateHandle = await nativeAudio.addListener('playbackState', event => onState?.(event));
      }
      configured = true;
    }
    return true;
  }

  async function stop() {
    if (!isNative) return;
    try { if (assetId) await nativeAudio.stop({ assetId }); } catch {}
    try { if (assetId) await nativeAudio.unload({ assetId }); } catch {}
    try { await playback.stop(); } catch {}
    assetId = '';
  }

  async function play(track) {
    if (!await configure()) return false;
    await stop();
    assetId = 'archive-' + Date.now().toString(36);
    const url = String(track.url || '').trim();
    if (!url) throw new Error('AUDIO_URL_MISSING');
    await nativeAudio.preload({
      assetId,
      assetPath: url,
      isUrl: /^https?:\/\//i.test(url),
      volume: 1,
      notificationMetadata: {
        title: track.title || 'تشغيل صوتي',
        artist: track.artist || 'Archive',
        album: 'Archive',
        artworkSource: track.cover || '',
      },
    });
    await playback.start({ title: track.title || 'تشغيل صوتي', artist: track.artist || 'Archive' });
    await nativeAudio.play({ assetId });
    return true;
  }

  async function pause() { if (isNative && assetId) await nativeAudio.pause({ assetId }); }
  async function resume() { if (isNative && assetId) await nativeAudio.resume({ assetId }); }
  async function seek(time) { if (isNative && assetId) await nativeAudio.setCurrentTime({ assetId, time }); }
  async function position() {
    if (!isNative || !assetId) return { currentTime: 0, duration: 0 };
    const [current, duration] = await Promise.all([
      nativeAudio.getCurrentTime({ assetId }).catch(() => ({ currentTime: 0 })),
      nativeAudio.getDuration({ assetId }).catch(() => ({ duration: 0 })),
    ]);
    return { currentTime: Number(current.currentTime || 0), duration: Number(duration.duration || 0) };
  }

  window.archiveNativeAudio = {
    available: isNative,
    configure,
    play,
    pause,
    resume,
    stop,
    seek,
    position,
    set onComplete(fn) { onComplete = fn; },
    set onState(fn) { onState = fn; },
  };
})();
