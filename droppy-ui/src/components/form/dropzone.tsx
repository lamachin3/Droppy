import React from 'react';
import { Controller, useFormContext } from 'react-hook-form';
import { useDropzone } from 'react-dropzone';
import { Icon } from '@iconify/react';
import { Box, Button, Typography, styled, alpha, useTheme } from '@mui/material';

interface FormDropzoneProps {
  name: string;
  onDrop?: (acceptedFiles: File[]) => void;
  accept?: Record<string, string[]>;
  maxFiles?: number;
  maxSize?: number;
  disabled?: boolean;
  multiple?: boolean;
  children?: React.ReactNode;
  showPreview?: boolean;
  value?: File[];
  onChange?: (files: File[]) => void;
}

const DropzoneContainer = styled(Box)(({ theme }) => ({
  border: `2px dashed ${alpha(theme.palette.primary.main, 0.5)}`,
  borderRadius: '8px',
  backgroundColor: alpha(theme.palette.background.default, 0.6),
  padding: '30px 20px',
  textAlign: 'center',
  cursor: 'pointer',
  transition: 'all 0.3s ease',
  minHeight: '150px',
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  justifyContent: 'center',
  gap: '16px',
  '&:hover': {
    borderColor: alpha(theme.palette.primary.main, 0.7),
    backgroundColor: alpha(theme.palette.primary.main, 0.1),
  },
  '&.dragActive': {
    borderColor: theme.palette.primary.main,
    backgroundColor: alpha(theme.palette.primary.main, 0.3),
  },
  '&.disabled': {
    opacity: 0.6,
    cursor: 'not-allowed',
  },
}));

const StyledButton = styled(Button)(({ theme }) => ({
  backgroundColor: "transparent",
  color: theme.palette.primary.contrastText,
  border: `1px solid ${alpha(theme.palette.primary.contrastText, 0.2)}`,
  borderRadius: '6px',
  padding: '8px 16px',
  textTransform: 'none',
  fontSize: '14px',
  fontWeight: 600,
  '&:hover': {
    backgroundColor: alpha(theme.palette.primary.main, 0.3),
    borderColor: alpha(theme.palette.primary.main, 0.7),
  },
}));

const FormDropzone: React.FC<FormDropzoneProps> = ({
  name = "",
  onDrop,
  accept = {
    'application/octet-stream': ['.exe', '.bin', '.raw', '.hex'],
  },
  maxFiles = 1,
  maxSize,
  disabled = false,
  multiple = false,
  children,
  showPreview = true,
}) => {
  const theme = useTheme();
  const { control } = useFormContext();

  // Helper functions
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileIcon = (filename: string): string => {
    const extension = filename.split('.').pop()?.toLowerCase();
    switch (extension) {
      case 'exe':
        return 'bi:filetype-exe';
      case 'bin':
        return 'bi:file-earmark-binary';
      case 'raw':
        return 'bi:filetype-raw';
      case 'hex':
        return 'bi:file-earmark-binary';
      default:
        return 'bi:file-earmark-code';
    }
  };

  const getAcceptedExtensions = () => {
    const extensions = Object.values(accept).flat();
    return extensions.join(', ');
  };

  return (
    <Controller
      name={name}
      control={control}
      defaultValue={[]}
      render={({ field: { value: files = [], onChange }, fieldState: { error } }) => {
        const onDropCallback = (acceptedFiles: File[]) => {
          const newFiles = multiple ? [...files, ...acceptedFiles] : acceptedFiles;
          onChange(newFiles); 
          if (onDrop) onDrop(acceptedFiles);
        };
    
        const removeFile = (index: number) => {
          const newFiles = files.filter((_: File, i: number) => i !== index);
          onChange(newFiles);
        };
    
        const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
          onDrop: onDropCallback,
          accept,
          maxFiles,
          maxSize,
          disabled,
          multiple,
        });

        return (
          <Box>
            {error && (
              <Typography sx={{ color: theme.palette.error.main, mt: 1 }}>
                {error.message}
              </Typography>
            )}
            {/* Dropzone Area */}
            <DropzoneContainer
              {...getRootProps()}
              className={`${
                isDragActive ? 'dragActive' : ''
              } ${disabled ? 'disabled' : ''}`}
            >
              <input {...getInputProps()} />
              
              <Icon 
                icon="solar:upload-linear" 
                width="48" 
                height="48" 
                style={{ color: theme.palette.primary.contrastText }}
              />
              
              <Typography
                variant="h6"
                sx={{
                  color: theme.palette.primary.contrastText,
                  fontWeight: 600,
                  fontSize: '18px',
                  marginBottom: '8px',
                }}
              >
                Drag & drop your payload{multiple ? 's' : ''} here
              </Typography>
              
              <Typography
                variant="body2"
                sx={{
                  color: alpha(theme.palette.primary.contrastText, 0.8),
                  fontSize: '13px',
                  marginBottom: '20px',
                }}
              >
                Supports {getAcceptedExtensions()} files
              </Typography>
              
              <StyledButton
                onClick={(e) => {
                  e.stopPropagation();
                  open();
                }}
                startIcon={<Icon icon="solar:folder-open-linear" width="16" height="16" />}
              >
                Browse Files
              </StyledButton>
              
              {children}
            </DropzoneContainer>

            {/* File Preview Section */}
            {showPreview && files.length > 0 && (
              <Box sx={{ mt: 2 }}>
                {files.map((file: File, index: number) => (
                  <Box
                    key={`${file.name}-${index}`}
                    sx={{
                      border: `1px solid ${alpha(theme.palette.primary.contrastText, 0.2)}`,
                      borderRadius: '8px',
                      padding: '14px',
                      backgroundColor: 'transparent',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      mb: index < files.length - 1 ? 1 : 0,
                    }}
                  >
                    <Box
                      sx={{
                        width: 'auto',
                        height: 'auto',
                        padding: '6px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        backgroundColor: alpha(theme.palette.primary.main, 0.2),
                        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                        borderRadius: '8px',
                        overflow: 'hidden',
                      }}
                    >
                      <Icon 
                        icon={getFileIcon(file.name)} 
                        width="20" 
                        height="20" 
                        color={theme.palette.primary.main} 
                      />
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Typography
                        variant="body1"
                        sx={{
                          color: theme.palette.primary.contrastText,
                          fontWeight: 600,
                          fontSize: '14px',
                        }}
                      >
                        {file.name}
                      </Typography>
                      <Typography
                        variant="body2"
                        sx={{
                          color: alpha(theme.palette.primary.contrastText, 0.7),
                          fontSize: '12px',
                        }}
                      >
                        {formatFileSize(file.size)}
                      </Typography>
                    </Box>
                    <Button
                      onClick={() => removeFile(index)}
                      sx={{
                        minWidth: 'auto',
                        padding: '4px',
                        color: alpha(theme.palette.primary.contrastText, 0.7),
                        '&:hover': {
                          color: theme.palette.error.main,
                          backgroundColor: alpha(theme.palette.error.main, 0.1),
                        },
                      }}
                    >
                      <Icon icon="solar:trash-bin-minimalistic-linear" width="16" height="16" />
                    </Button>
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        );
      }}
    />
  );
};

export default FormDropzone;