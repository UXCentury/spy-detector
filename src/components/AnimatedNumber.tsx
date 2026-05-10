"use client";

import { useMotionValueEvent, useSpring } from "framer-motion";
import { useEffect, useState } from "react";

type AnimatedNumberProps = {
  value: number;
  className?: string;
  format?: (n: number) => string;
};

export function AnimatedNumber({
  value,
  className,
  format = (n) => n.toLocaleString(),
}: AnimatedNumberProps) {
  const spring = useSpring(0, { stiffness: 220, damping: 32, mass: 0.35 });
  const [text, setText] = useState(() => format(Math.round(spring.get())));

  useMotionValueEvent(spring, "change", (v) => {
    setText(format(Math.round(v)));
  });

  useEffect(() => {
    spring.set(value);
  }, [value, spring]);

  return <span className={className}>{text}</span>;
}
