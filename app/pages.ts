/**
 * HTML pages. Every value that comes from a request or the store goes through escapeHtml, except where the
 * reflected-xss defect deliberately skips it.
 */
import type { Note } from './store.ts';

/** Escapes the five characters that can change the meaning of HTML text or attribute values. */
export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)} | NoteVault</title>
    <link rel="stylesheet" href="/styles.css" />
  </head>
  <body>
    <header><a href="/">NoteVault</a> <nav><a href="/login">Sign in</a> <a href="/search?q=holiday">Search</a></nav></header>
    <main>
${body}
    </main>
  </body>
</html>
`;
}

export function homePage(): string {
  return layout(
    'Home',
    `      <h1>Your notes, kept private</h1>
      <p>NoteVault is a deliberately small demo app for security testing.</p>
      <form action="/search" method="get">
        <label for="q">Search public tips</label>
        <input id="q" name="q" />
        <button>Search</button>
      </form>`,
  );
}

export function loginPage(csrfToken: string, message = ''): string {
  return layout(
    'Sign in',
    `      <h1>Sign in</h1>
      ${message ? `<p role="alert">${escapeHtml(message)}</p>` : ''}
      <form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
        <label for="name">User name</label>
        <input id="name" name="name" autocomplete="username" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" />
        <button>Sign in</button>
      </form>`,
  );
}

/** The search term is shown back to the user; `escape` is false only in the vulnerable build. */
export function searchPage(term: string, results: string[], escape: boolean): string {
  const shown = escape ? escapeHtml(term) : term;
  const items = results.map((r) => `        <li>${escapeHtml(r)}</li>`).join('\n');
  return layout(
    'Search',
    `      <h1>Results for ${shown}</h1>
      <ul>
${items || '        <li>No tips found.</li>'}
      </ul>`,
  );
}

export function notesPage(name: string, notes: Note[]): string {
  const items = notes.map((n) => `        <li><strong>${escapeHtml(n.title)}</strong>: ${escapeHtml(n.text)}</li>`);
  return layout(
    'My notes',
    `      <h1>Notes of ${escapeHtml(name)}</h1>
      <ul>
${items.join('\n')}
      </ul>
      <form action="/logout" method="post"><button>Sign out</button></form>`,
  );
}

export function expiredPage(): string {
  return layout(
    'Sign in',
    `      <h1>The sign-in form has expired</h1>
      <p><a href="/login">Open the sign-in page again</a> and try once more.</p>`,
  );
}

export const NOT_FOUND_PAGE = layout('Not found', '      <h1>Page not found</h1>');
