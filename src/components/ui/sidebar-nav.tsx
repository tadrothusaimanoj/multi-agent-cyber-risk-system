import * as React from "react";
import { LucideIcon } from "lucide-react";

interface SidebarNavProps {
  sections: {
    title?: string;
    items: {
      label: string;
      href: string;
      icon: LucideIcon;
      count?: string | number;
    }[];
  }[];
  activeHref?: string;
  onSelect?: (item: { href: string; label: string }, e: React.MouseEvent) => void;
  className?: string;
}

export function SidebarNav({ sections, activeHref, onSelect, className }: SidebarNavProps) {
  return (
    <nav aria-label="Main" className={className}>
      {sections.map((section, sIdx) => {
        const sectionId = `sidebar-nav-section-${sIdx}`;
        return (
          <div key={sIdx} className="mb-4 last:mb-0">
            {section.title && (
              <h3 
                id={sectionId}
                className="px-3 pt-5 pb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500"
              >
                {section.title}
              </h3>
            )}
            <ul aria-labelledby={section.title ? sectionId : undefined}>
              {section.items.map((item, iIdx) => {
                const isActive = item.href === activeHref && item.href !== 'home';
                const Icon = item.icon;
                
                return (
                  <li key={iIdx} className="mb-1 last:mb-0">
                    <a
                      href={`#${item.href}`}
                      onClick={(e) => onSelect?.(item, e)}
                      aria-current={isActive ? "page" : undefined}
                      className={`flex h-10 items-center gap-3 rounded-lg px-3 text-sm font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-900 ${
                        isActive 
                          ? "bg-zinc-800 text-zinc-100" 
                          : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100"
                      }`}
                    >
                      <Icon 
                        className={`size-5 shrink-0 stroke-[1.5] ${
                          isActive ? "text-zinc-100" : "text-zinc-500"
                        }`} 
                      />
                      <span className="truncate">{item.label}</span>
                      
                      {item.count !== undefined && (
                        <span className="ml-auto text-sm tabular-nums text-zinc-400">
                          {item.count}
                        </span>
                      )}
                    </a>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}
