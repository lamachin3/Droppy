export const themeConfig = {
  /** **************************************
   * Base
   *************************************** */
  classesPrefix: 'minimal',
  /** **************************************
   * Typography
   *************************************** */
  typography: {
    htmlFontSize: 16,
    fontSize: 14,
    fontFamily: 'JetBrains Mono',
    fontWeightLight: 300,
    fontWeightRegular: 400,
    fontWeightMedium: 600,
    fontWeightBold: 700,
  },
  fontFamily: {
    primary: 'JetBrains Mono',
    secondary: 'Barlow',
  },
  /** **************************************
   * Palette
   *************************************** */
  palette: {
    primary: {
      lighter: '#f7a1a1',
      light: '#f37272',
      main: '#ef4343',
      dark: '#d31212',
      darker: '#8d0c0c',
      contrastText: '#ebebeb',
    },
    secondary: {
      lighter: '#ff7b75',
      light: '#ff3a30',
      main: '#ea0b00',
      dark: '#af0800',
      darker: '#750500',
      contrastText: '#ebebeb',
    },
    info: {
      lighter: '#CAFDF5',
      light: '#61F3F3',
      main: '#6666ff',
      dark: '#006C9C',
      darker: '#003768',
      contrastText: '#FFFFFF',
    },
    success: {
      lighter: '#D3FCD2',
      light: '#77ED8B',
      main: '#22C55E',
      dark: '#118D57',
      darker: '#065E49',
      contrastText: '#ffffff',
    },
    warning: {
      lighter: '#FFF5CC',
      light: '#FFD666',
      main: '#f0c414',
      dark: '#B76E00',
      darker: '#7A4100',
      contrastText: '#1C252E',
    },
    error: {
      lighter: '#FFE9D5',
      light: '#FFAC82',
      main: '#fe0805',
      dark: '#B71D18',
      darker: '#7A0916',
      contrastText: '#FFFFFF',
    },
    grey: {
      '50': '#FCFDFD',
      '100': '#F9FAFB',
      '200': '#F4F6F8',
      '300': '#DFE3E8',
      '400': '#C4CDD5',
      '500': '#919EAB',
      '600': '#637381',
      '700': '#454F5B',
      '800': '#1C252E',
      '900': '#141A21',
    },
    common: { black: '#000000', white: '#FFFFFF' },
    text: {
      primary: '#ef4343',
      secondary: '#fe0805',
      disabled: '#ef434386',
      divider: '#ef4343',
    },
    background: {
      default: '#050505',
      paper: '#0e0e0e',
      fileCard: '#141A21',
    },
    action: {
      active: 'rgba(0, 0, 0, 0.54)',
      hover: 'rgba(0, 0, 0, 0.04)',
      selected: 'rgba(0, 0, 0, 0.08)',
      disabled: 'rgba(0, 0, 0, 0.26)',
      disabledBackground: 'rgba(0, 0, 0, 0.12)',
      focus: 'rgba(0, 0, 0, 0.12)',
    },
  },
};