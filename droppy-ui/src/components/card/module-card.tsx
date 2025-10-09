import { Box, Card, CardHeader, CardContent, CardActions, Typography, useTheme, alpha } from '@mui/material';
import React from 'react';
import { CardButton } from '../button';
import { StatusBadge } from '../badge';


export default function ModuleCard({ icon, title="", status="", content, buttonText, onAction }: ModuleCardProps) {
  const theme = useTheme();

  const isUpcoming = status?.toLowerCase() === 'upcoming';

  function statusToColor(status: string) {
    switch (status.toLowerCase()) {
      case 'new':
        return theme.palette.success.main;
      case 'beta':
        return theme.palette.warning.main;
      case 'upcoming':
        return theme.palette.text.secondary;
      default:
        return theme.palette.text.secondary;
    }
  };

  return (
    <Card
      elevation={0}
      sx={{
        height: "100%",
        minWidth: 275,
        padding: 2,
        color: "lightgray",
        borderRadius: 2.5,
        border: '0.1px solid',
        borderColor: isUpcoming 
          ? alpha(theme.palette.text.disabled, 0.2)
          : alpha(theme.palette.background.paper, 0.2),
        backgroundColor: isUpcoming 
          ? alpha(theme.palette.action.disabledBackground, 0.1)
          : theme.palette.background.paper,
        transition: 'all 0.3s ease',
        display: 'flex',
        flexDirection: 'column',
        opacity: isUpcoming ? 0.7 : 1,
        pointerEvents: isUpcoming ? 'none' : 'auto',
        '&:hover': {
          border: '0.1px solid',
          borderColor: isUpcoming 
            ? alpha(theme.palette.text.disabled, 0.3)
            : alpha(theme.palette.primary.main, 0.5),
        },
      }}
    >
      <CardHeader
        avatar={
          <Box
            sx={{
              width: "auto",
              height: "auto",
              padding: 1.5,
              borderRadius: 2.5,
              border: '1px solid',
              borderColor: alpha(theme.palette.primary.main, 0.3),
              backgroundColor: alpha(theme.palette.primary.main, 0.1),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {icon}
          </Box>
        }
        title={
          <Box display="flex" justifyContent="space-between" alignItems="center" width="100%">
            <Typography variant="h6" fontWeight="bold">
              {title.toUpperCase()}
            </Typography>

            {status && (
              <StatusBadge text={`[${status.toUpperCase()}]`} color={statusToColor(status)} />
            )}
          </Box>
        }
      />
      <CardContent
        sx={{
          flex: '1 0 auto',
          width: '100%',
          paddingBottom: 0,
        }}
      >
        {content}
      </CardContent>
      <CardActions sx={{ mt: 1.5, width: '100%' }}>
        {buttonText && (
          <CardButton 
            onClick={onAction} 
            fullWidth 
            disabled={isUpcoming}
            sx={{
              '&.Mui-disabled': {
                color: alpha(theme.palette.text.secondary, 0.5),
                borderColor: alpha(theme.palette.text.secondary, 0.2),
              },
            }}
          >
            {isUpcoming ? 'Coming Soon' : buttonText}
          </CardButton>
        )}
      </CardActions>
    </Card>
  );
}

interface ModuleCardProps {
  icon: React.ReactNode;
  title: string;
  status?: string;
  content: React.ReactNode;
  buttonText?: string;
  onAction?: () => void;
}