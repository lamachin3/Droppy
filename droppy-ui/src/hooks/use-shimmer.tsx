import { useMemo } from 'react';

export const useShimmer = () => {

  const shimmerStyles = useMemo(() => ({
    position: 'relative',
    overflow: 'hidden',
    '&::before': {
      content: '""',
      position: 'absolute',
      top: 0,
      left: '-100%',
      width: '100%',
      height: '100%',
      background: `linear-gradient(
        90deg,
        transparent,
        rgba(255, 255, 255, 0.012),
        rgba(255, 255, 255, 0.025),
        rgba(255, 255, 255, 0.012),
        transparent
      )`,
      animation: 'shimmer 5s ease-in-out infinite',
      pointerEvents: 'none',
    },
    '@keyframes shimmer': {
      '0%': {
        left: '-100%',
      },
      '50%': {
        left: '100%',
      },
      '100%': {
        left: '100%',
      },
    },
  }), []);

  return { shimmerStyles };
};