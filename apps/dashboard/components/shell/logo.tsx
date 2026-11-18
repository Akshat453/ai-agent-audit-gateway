/** Original product mark: a shield containing two interlocked chain links (hash-chained,
 *  guarded evidence). Pure SVG, no external asset. */
export function LogoMark({ className = "size-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} role="img" aria-hidden="true">
      <path d="M16 2.5 4.5 6.8v8.4c0 7.3 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7 11.5-14.3V6.8L16 2.5Z" className="fill-brand-9" />
      <path d="M16 4.6 6.5 8.2v7c0 6.2 4 10.7 9.5 12.3 5.5-1.6 9.5-6.1 9.5-12.3v-7L16 4.6Z" className="fill-brand-10" />
      <g fill="none" stroke="white" strokeWidth={2.1} strokeLinecap="round">
        <rect x="8.6" y="12.2" width="9" height="6" rx="3" transform="rotate(-35 13.1 15.2)" />
        <rect x="14.4" y="12.2" width="9" height="6" rx="3" transform="rotate(-35 18.9 15.2)" />
      </g>
    </svg>
  );
}
