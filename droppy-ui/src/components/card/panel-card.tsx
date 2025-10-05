import {
  Card,
  CardHeader,
  CardContent,
  CardActions,
  Typography,
  useTheme,
  alpha,
} from '@mui/material';
import type { SxProps, Theme } from '@mui/material';
import type { ReactNode } from 'react';
import { CardButton } from '@/components';

interface PanelCardProps {
  icon: ReactNode;
  title?: string;
  subheader?: string;
  children?: ReactNode;
  buttonText?: string;
  onAction?: () => void;
  sx?: SxProps<Theme>;
}

export default function PanelCard({
  icon,
  title = '',
  subheader = '',
  children,
  buttonText = '',
  onAction,
  sx,
}: PanelCardProps) {
  const theme = useTheme();

  return (
    <Card
      elevation={0}
      sx={{
        minWidth: 275,
        padding: 2,
        color: 'lightgray',
        borderRadius: 2.5,
        border: '0.5px solid',
        borderColor: alpha(theme.palette.primary.contrastText, 0.1),
        backgroundColor: theme.palette.background.paper,
        transition: 'border-color 0.3s ease',
        ...sx,
      }}
    >
      {(icon || title) && <CardHeader
        avatar={icon}
        title={
          <Typography variant="h6" fontWeight="bold">
            {title.toUpperCase()}
          </Typography>
        }
        subheader={subheader}
        sx={{ py: 0.5 }}
        slotProps={{
          subheader: {
            sx: {
              fontWeight: 600,
              color: theme.palette.grey[600],
            },
          },
        }}
      />}
      {children && <CardContent sx={{ pt: 3 }}>{children}</CardContent>}
      {buttonText && (
        <CardActions>
          <CardButton onClick={onAction} fullWidth>
            {buttonText}
          </CardButton>
        </CardActions>
      )}
    </Card>
  );
}