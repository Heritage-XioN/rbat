"use client";

import { Transition } from "@headlessui/react";

interface TransitionWrapperProps {
  children: React.ReactNode;
  show: boolean;
  delay?: string; // Optional Tailwind delay utilities like "delay-100", "delay-200"
}

export function TransitionWrapper({
  children,
  show,
  delay = "",
}: TransitionWrapperProps) {
  return (
    <Transition
      as="div"
      show={show}
      unmount
      className="w-full h-full"
      enter={`transition-all duration-500 ease-out ${delay}`}
      enterFrom="opacity-0 translate-y-4"
      enterTo="opacity-100 translate-y-0"
      leave="transition-all duration-300 ease-in"
      leaveFrom="opacity-100 translate-y-0"
      leaveTo="opacity-0 translate-y-4"
    >
      {children}
    </Transition>
  );
}
