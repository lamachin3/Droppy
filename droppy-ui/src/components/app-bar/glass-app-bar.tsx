import React, { type ReactNode } from 'react';
import { AppBar, Toolbar } from '@mui/material';
import { styled } from '@mui/material/styles';


const StyledAppBar = styled(AppBar)(() => ({
  background: 'rgba(255, 255, 255, 0.05)',
  boxShadow: '0 4px 30px rgba(0, 0, 0, 0.1)',
  backdropFilter: 'blur(10px)',
  WebkitBackdropFilter: 'blur(10px)',
  borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
  position: 'fixed',
  top: 0,
  left: 0,
  right: 0,
  zIndex: 1100,
}));

const ContentWrapper = styled(Toolbar)({
  position: 'relative',
  zIndex: 2,
});

interface GlassAppBarProps {
  children: ReactNode;
}

export const GlassAppBar: React.FC<GlassAppBarProps> = ({ children }) => {
  return (
    <StyledAppBar>
      <ContentWrapper>
        {children}
      </ContentWrapper>
    </StyledAppBar>
  );
};
