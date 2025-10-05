import React from 'react';
import { Box } from '@mui/material';
import type { BoxProps } from '@mui/system';
import { keyframes, styled } from '@mui/material/styles';

// Pulse animation
const pulse = keyframes`
  0%, 100% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.6);
    opacity: 0.6;
  }
`;

// Props for customization
interface PulsingDotProps extends BoxProps {
  color?: string; // Accepts any valid CSS color (e.g., 'red', '#00FF00')
}

// Styled dot
const Dot = styled(Box, {
  shouldForwardProp: (prop) => prop !== 'color',
})<PulsingDotProps>(({ color = 'red' }) => ({
  width: 5,
  height: 5,
  borderRadius: '50%',
  backgroundColor: color,
  animation: `${pulse} 1.5s ease-in-out infinite`,
}));

// Component
const PulsingDot: React.FC<PulsingDotProps> = ({ color = 'red', ...rest }) => {
  return <Dot color={color} {...rest} />;
};

export default PulsingDot;
