import React, { useState, useRef, useEffect } from 'react';
import {
  alpha,
  Badge,
  Box,
  Button,
  useTheme,
} from '@mui/material';
import { Icon } from '@iconify/react';

interface TabData {
  id: string;
  icon: string;
  label: string;
  content: React.ReactNode;
  disabled?: boolean;
}

import type { SxProps, Theme } from '@mui/material';

interface SlidingTabProps {
  tabs: TabData[];
  defaultTab?: string;
  onChange?: (tabId: string) => void;
  sx?: SxProps<Theme>;
}

export default function SlidingTab({ tabs, defaultTab, onChange, sx = {} }: SlidingTabProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(defaultTab || tabs[0]?.id);
  const [indicatorStyle, setIndicatorStyle] = useState({ width: 0, left: 0 });
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);

  const activeIndex = tabs.findIndex(tab => tab.id === activeTab);
  const activeTabData = tabs.find(tab => tab.id === activeTab);

  useEffect(() => {
    const updateIndicator = () => {
      const activeTabElement = tabRefs.current[activeIndex];
      const containerElement = containerRef.current;
      
      if (activeTabElement && containerElement) {
        const containerRect = containerElement.getBoundingClientRect();
        const tabRect = activeTabElement.getBoundingClientRect();
        
        const containerPadding = 8;
        
        setIndicatorStyle({
          width: tabRect.width,
          left: tabRect.left - containerRect.left - containerPadding,
        });
      }
    };

    updateIndicator();
    window.addEventListener('resize', updateIndicator);
    return () => window.removeEventListener('resize', updateIndicator);
  }, [activeIndex]);

  const handleTabClick = (tabId: string) => {
    setActiveTab(tabId);
    if (onChange) {
      onChange(tabId);
    }
  };

  return (
    <Box sx={[{ width: '100%', mx: 'auto' }, ...(Array.isArray(sx) ? sx : [sx])]}>
      {/* Tab Headers */}
      <Box
        ref={containerRef}
        sx={{
          position: 'relative',
          backgroundColor: theme.palette.background.default,
          borderRadius: 2,
          p: 1,
          mb: 3,
        }}
      >
        {/* Sliding Indicator */}
        <Box
          sx={{
            position: 'absolute',
            top: 2,
            bottom: 2,
            my: 0.6,
            backgroundColor: alpha(theme.palette.grey[600], 0.2),
            borderRadius: 1.5,
            transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
            width: `${indicatorStyle.width}px`,
            transform: `translateX(${indicatorStyle.left}px)`,
            zIndex: 1,
          }}
        />
        
        {/* Tab Buttons */}
        <Box sx={{ position: 'relative', display: 'flex', zIndex: 2 }}>
          {tabs.map((tab, index) => (
            <Button
              disableRipple
              key={tab.id}
              ref={(el: HTMLButtonElement | null) => {
                tabRefs.current[index] = el;
              }}
              onClick={() => handleTabClick(tab.id)}
              sx={{
                flex: 1,
                borderRadius: 1.5,
                fontFamily: theme.typography.fontFamily,
                fontWeight: 500,
                fontSize: '0.875rem',
                textTransform: 'none',
                color: activeTab === tab.id 
                  ? theme.palette.primary.main 
                  : theme.palette.grey[500],
                backgroundColor: 'transparent',
                transition: 'color 0.2s ease-in-out',
                '&:hover': {
                  backgroundColor: 'transparent',
                  color: activeTab === tab.id 
                    ? theme.palette.primary.main
                    : theme.palette.grey[300],
                },
                '&:focus': {
                  outline: 'none',
                },
                '&:disabled': {
                  color: theme.palette.grey[800],
                  cursor: 'not-allowed',
                },
              }}
              disabled={tab?.disabled || false}
            >
              <Icon icon={tab.icon} width="18" height="18" style={{ marginRight: '0.3rem', color: "inherit" }} />
              {tab.label}
              {tab.badge && (
                <Badge 
                  variant="dot" 
                  color="primary" 
                  sx={{ 
                    ml: 2,
                    '& .MuiBadge-badge': {
                      width: '5px',
                      minWidth: '5px',
                      height: '5px',
                    }
                  }} 
                />
              )}
            </Button>
          ))}
        </Box>
      </Box>

      {/* Tab Content */}
      <Box>
        {activeTabData?.content}
      </Box>
    </Box>
  );
}