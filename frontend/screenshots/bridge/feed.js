/**
 * Feeds: events that keep arriving.
 *
 * A scene's `events` list says "an alert at four seconds", which is right for a
 * still photograph. It cannot say "messages, continuously, for as long as
 * anyone is watching" — and that is precisely what a syslog receiver looks
 * like. A screenshot of a log viewer with a frozen counter is a screenshot of a
 * dead product.
 *
 * The messages are the fixture's own, cycled with fresh timestamps and fresh
 * ids, so the demo never invents a line the story does not contain.
 */

import { MESSAGES, STATS, NOW, SERVER_STATUS as STATUS, messagesByLevel, topSources } from '../fixtures.js';

// A quieter slice to circulate: the background traffic, not the incident. The
// incident is already on screen from the seed, and replaying a crisis on a loop
// would read as an alarm that never clears.
const BACKGROUND = MESSAGES.filter((m) => m.severity >= 5);

let serial = 0;
let total = STATS.totalMessages;
const levels = { ...messagesByLevel() };

function nextMessage() {
  const src = BACKGROUND[serial % BACKGROUND.length];
  serial += 1;
  total += 1;
  levels[src.severityLabel] = (levels[src.severityLabel] || 0) + 1;

  // Carry on from where the story left off rather than from the wall clock.
  // One rule serves both uses: in the demo the story is anchored at page load,
  // so this is "just now"; in the screenshots it is anchored to a fixed
  // evening, so the arriving lines continue that evening instead of being
  // stamped with the day the pictures happened to be taken.
  const at = new Date(NOW.getTime() + serial * 1000).toISOString();
  return { ...src, id: `live-${serial}`, timestamp: at, receivedAt: at };
}

export const FEEDS = {
  /**
   * The live view: a small batch of messages and a refreshed set of counters,
   * which is the pair the backend emits (`syslog:messages` in batches,
   * `syslog:stats` on its own cadence).
   */
  live(tick) {
    // The opening beat hands over the whole evening at once: the application
    // fills its list from events alone, so this IS its history.
    if (tick === 0) {
      return [
        { name: 'syslog:messages', payload: MESSAGES },
        { name: 'syslog:stats', payload: { ...STATS } },
        { name: 'syslog:status', payload: STATUS },
      ];
    }

    const batch = [nextMessage()];
    if (tick % 3 === 0) batch.push(nextMessage());

    const events = [{ name: 'syslog:messages', payload: batch }];

    if (tick % 2 === 0) {
      events.push({
        name: 'syslog:stats',
        payload: {
          ...STATS,
          totalMessages: total,
          messagesByLevel: { ...levels },
          topSources: topSources(),
          // A rate that breathes rather than a straight line.
          messagesPerSec: Math.round((7 + 4 * Math.sin(tick / 3)) * 10) / 10,
          bufferUsed: Math.min(total, STATS.bufferMax),
        },
      });
    }
    return events;
  },
};
