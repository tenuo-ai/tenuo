const allowedPath = "/data/report.txt";
const deniedPath = "/etc/passwd";

export default function Home() {
  return (
    <main>
      <h1>Tenuo on the Next.js Node runtime</h1>
      <p>
        The route handler protects a server-side operation. Tenuo permits paths
        under <code>/data</code> and denies paths outside it.
      </p>
      <ul>
        <li>
          <a href={`/api/read?path=${encodeURIComponent(allowedPath)}`}>
            Try an allowed request
          </a>
        </li>
        <li>
          <a href={`/api/read?path=${encodeURIComponent(deniedPath)}`}>
            Try a denied request
          </a>
        </li>
      </ul>
    </main>
  );
}
