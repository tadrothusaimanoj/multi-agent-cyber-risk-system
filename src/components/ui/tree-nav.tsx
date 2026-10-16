"use client";

import * as React from "react";
import { animate, motion, useMotionValue, useTransform } from "motion/react";

import { cn } from "@/lib/utils";
import { usePrefersReducedMotion } from "@/components/ui/tree-nav-utils/use-typewriter";

export interface TreeNavItem {
  label: string;
  href: string;
  badge?: string;
  external?: boolean;
}

type LinkComponent =
  | "a"
  | React.ComponentType<
      React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }
    >;

export interface TreeNavProps {
  items: TreeNavItem[];
  activeHref?: string;
  followHover?: boolean;
  linkComponent?: LinkComponent;
  onSelect?: (
    item: TreeNavItem,
    event: React.MouseEvent<HTMLAnchorElement>,
  ) => void;
  className?: string;
}

const ROW_H = 32;
const MARKER = 7;
const RAIL_X = 10;

const GLIDE = { type: "spring", visualDuration: 0.22, bounce: 0 } as const;
const FADE = { duration: 0.12, ease: "easeOut" } as const;

export function TreeNav({
  items,
  activeHref,
  followHover = true,
  linkComponent: Link = "a",
  onSelect,
  className,
}: TreeNavProps) {
  const listRef = React.useRef<HTMLUListElement>(null);
  const rowRefs = React.useRef<(HTMLLIElement | null)[]>([]);
  const centersRef = React.useRef<number[]>([]);
  const hoveredRef = React.useRef<number | null>(null);
  const reduced = usePrefersReducedMotion();
  const activeIndex = items.findIndex((item) => item.href === activeHref);
  const reducedRef = React.useRef(reduced);
  const activeRef = React.useRef(activeIndex);
  React.useLayoutEffect(() => {
    reducedRef.current = reduced;
    activeRef.current = activeIndex;
  });

  const [end, setEnd] = React.useState(0);
  const [measured, setMeasured] = React.useState(false);

  const centerY = useMotionValue(0);
  const visibility = useMotionValue(0);
  const pillY = useTransform(centerY, (v) => v - ROW_H / 2);
  const markerY = useTransform(centerY, (v) => v - MARKER / 2);
  const accentScale = useTransform(centerY, (v) =>
    end > 0 ? Math.min(1, v / end) : 0,
  );

  const moveTo = React.useCallback(
    (index: number | null, immediate = false) => {
      const centers = centersRef.current;
      if (index === null || index < 0 || index >= centers.length) {
        animate(visibility, 0, FADE);
        return;
      }
      const target = centers[index];
      const jump = immediate || reducedRef.current || visibility.get() < 0.05;
      if (jump) centerY.jump(target);
      else animate(centerY, target, GLIDE);
      animate(visibility, 1, FADE);
    },
    [centerY, visibility],
  );

  React.useLayoutEffect(() => {
    const list = listRef.current;
    if (!list) return;
    const measure = () => {
      const next = rowRefs.current
        .slice(0, items.length)
        .map((el) => (el ? el.offsetTop + el.offsetHeight / 2 : 0));
      centersRef.current = next;
      setEnd(next.length > 0 ? next[next.length - 1] : 0);
      setMeasured(true);
      moveTo(hoveredRef.current ?? activeRef.current, true);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(list);
    return () => observer.disconnect();
  }, [items.length, moveTo]);

  React.useEffect(() => {
    if (hoveredRef.current === null) moveTo(activeIndex);
  }, [activeIndex, moveTo]);

  const enter = (index: number) => {
    if (!followHover) return;
    hoveredRef.current = index;
    moveTo(index);
  };
  const leave = () => {
    if (!followHover) return;
    hoveredRef.current = null;
    moveTo(activeRef.current);
  };

  return (
    <ul
      ref={listRef}
      className={cn("relative flex flex-col gap-0.5 ps-6", className)}
      onPointerLeave={leave}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-y-0 start-0 w-5"
      >
        <span
          className="absolute top-0 w-px bg-zinc-800"
          style={{ insetInlineStart: RAIL_X - 0.5, height: end }}
        />
        <span
          className="absolute size-1 rounded-full bg-zinc-800"
          style={{ insetInlineStart: RAIL_X - 2, top: end - 2 }}
        />
        <motion.span
          className="absolute top-0 w-px origin-top bg-indigo-400 will-change-transform"
          style={{
            insetInlineStart: RAIL_X - 0.5,
            height: end,
            scaleY: accentScale,
            opacity: visibility,
          }}
        />
        <motion.span
          className="absolute top-0 rounded-[1px] bg-indigo-400 will-change-transform"
          style={{
            insetInlineStart: RAIL_X - MARKER / 2,
            width: MARKER,
            height: MARKER,
            y: markerY,
            rotate: 45,
            opacity: visibility,
          }}
        />
      </span>

      <motion.span
        aria-hidden
        className="pointer-events-none absolute end-0 start-6 top-0 rounded-lg bg-zinc-900 will-change-transform"
        style={{ height: ROW_H, y: pillY, opacity: visibility }}
      />

      {items.map((item, index) => {
        const isActive = index === activeIndex;
        return (
          <li
            key={item.href}
            ref={(el) => {
              rowRefs.current[index] = el;
            }}
            className="relative"
            onPointerEnter={() => enter(index)}
          >
            <Link
              href={item.href}
              target={item.external ? "_blank" : undefined}
              rel={item.external ? "noreferrer" : undefined}
              aria-current={isActive ? "page" : undefined}
              onClick={onSelect ? (event) => onSelect(item, event) : undefined}
              onFocus={() => enter(index)}
              onBlur={leave}
              className={cn(
                "flex h-8 items-center gap-2 rounded-lg px-3 text-[13px] leading-5 antialiased transition-colors duration-150 ease-out",
                isActive && !measured && "bg-zinc-900",
                isActive
                  ? "font-medium text-zinc-100"
                  : "font-normal text-zinc-400 hover:text-zinc-100",
              )}
            >
              <span className="truncate">{item.label}</span>
              {item.badge && (
                <span className="inline-flex h-[18px] shrink-0 items-center rounded-[6px] bg-indigo-500/15 px-[5px] text-xs font-medium leading-none text-indigo-300">
                  {item.badge}
                </span>
              )}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

export default TreeNav;
