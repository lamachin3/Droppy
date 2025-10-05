// src/theme/create-app-theme.ts
import { createTheme } from '@mui/material/styles'
import { themeConfig } from './theme-config'

export const appTheme = () => {
  return createTheme({
    palette: {
      mode: 'dark', // or 'light'
      primary: {
        main: themeConfig.palette.primary.main,
        light: themeConfig.palette.primary.light,
        dark: themeConfig.palette.primary.darker,
        contrastText: themeConfig.palette.primary.contrastText,
      },
      secondary: {
        main: themeConfig.palette.secondary.main,
        light: themeConfig.palette.secondary.light,
        dark: themeConfig.palette.secondary.dark,
        contrastText: themeConfig.palette.secondary.contrastText,
      },
      error: {
        main: themeConfig.palette.error.main,
      },
      warning: {
        main: themeConfig.palette.warning.main,
      },
      info: {
        main: themeConfig.palette.info.main,
      },
      success: {
        main: themeConfig.palette.success.main,
      },
      background: themeConfig.palette.background,
      text: themeConfig.palette.text,
      common: themeConfig.palette.common,
      action: themeConfig.palette.action,
    },
    typography: themeConfig.typography,
    spacing: themeConfig.spacing,
    breakpoints: themeConfig.breakpoints,
  })
}
