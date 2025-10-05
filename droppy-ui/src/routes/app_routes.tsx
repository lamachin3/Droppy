import { Routes, Route } from 'react-router-dom'
import { Home } from '@/pages/home'
import { Login, Register } from '@/pages/auth'
import { ProtectedRoute, PublicRoute } from '@/components';
import { BasicDropper } from '@/pages/basic-dropper';
import { AdvancedDropper } from '@/pages/advanced-dropper';
import { FileDetails } from '@/pages/file-details';

export const ROUTES = {
  HOME: '/',
  LOGIN: '/login',
  REGISTER: '/register',
  BASIC_DROPPER: '/basic-dropper',
  ADVANCED_DROPPER: '/advanced-dropper',
  FILE_DETAILS: '/file-details/:id',
}

export function AppRoutes() {
  return (
    <Routes>
      <Route 
        path={ROUTES.HOME} 
        element={<ProtectedRoute element={<Home />} />} 
      />
      
      <Route 
        path={ROUTES.LOGIN} 
        element={<PublicRoute element={<Login />} />} 
      />
      <Route 
        path={ROUTES.REGISTER} 
        element={<PublicRoute element={<Register />} />} 
      />
      
      <Route 
        path="*" 
        element={<ProtectedRoute element={<Home />} />} 
      />
      
      <Route 
        path={ROUTES.BASIC_DROPPER} 
        element={<ProtectedRoute element={<BasicDropper />} />} 
      />

      <Route 
        path={ROUTES.ADVANCED_DROPPER} 
        element={<ProtectedRoute element={<AdvancedDropper />} />} 
      />
      
      <Route 
        path={ROUTES.FILE_DETAILS} 
        element={<ProtectedRoute element={<FileDetails />} />} 
      />
    </Routes>
  )
}
