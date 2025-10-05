import React from 'react';
import { Header } from '@/layouts';
import { Container } from '@mui/material';


export default function AdvancedDropperLayout({ children }: AdvancedDropperLayoutProps) {
  return (
    <>
      <Header />
      <Container maxWidth="lg" sx={{ py: 10 }}>
        {children}
      </Container>
    </>
  );
};

interface AdvancedDropperLayoutProps {
  children: React.ReactNode;
}
