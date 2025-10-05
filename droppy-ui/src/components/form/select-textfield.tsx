import { useFormContext, Controller } from "react-hook-form";
import { alpha, Box, TextField, Select, MenuItem, useTheme, type TextFieldProps} from "@mui/material";

interface SelectTextFieldProps {
	filenameField: string;
	extensionField: string;
	label?: string;
	placeholder?: string;
	extensions?: string[];
	sx?: TextFieldProps['sx'];
}

export default function FormSelectTextField({
	filenameField,
	extensionField,
	label = "Output Filename",
	placeholder = "",
	extensions = ['.exe'],
	sx
}: SelectTextFieldProps) {
	const theme = useTheme();
	const { control } = useFormContext();
	
	const defaultSx = {
		color: theme.palette.primary.main,
		width: '100%',
		border: '0.5px solid',
		borderColor: alpha(theme.palette.primary.contrastText, 0.2),
		borderRadius: 2,
		backgroundColor: alpha(theme.palette.background.default, 0.6),
		'&:focus-within': {
			borderColor: alpha(theme.palette.primary.main, 0.8),
		},
		'& .MuiFilledInput-root': {
			backgroundColor: 'transparent !important',
			'&:before': { borderBottom: 'none' },
			'&:after': { borderBottom: 'none' },
			'&:hover': {
				backgroundColor: 'transparent !important',
				'&:before': { borderBottom: 'none' },
			},
			'&.Mui-focused': {
				backgroundColor: 'transparent !important',
			},
			'&.Mui-disabled': {
				backgroundColor: 'transparent !important',
			},
		},
		'&:hover .MuiFilledInput-root': {
			backgroundColor: 'transparent',
			'&:before': { borderBottom: 'none' },
			'&:after': { borderBottom: 'none' },
			'&:hover:before': { borderBottom: 'none' },
		},
		'& .MuiInputLabel-root': {
			color: alpha(theme.palette.primary.contrastText, 0.8),
		},
		'& .MuiInputLabel-root.Mui-focused': {
			color: alpha(theme.palette.primary.contrastText, 0.8),
		},
	};
	
	const selectSx = {
		minWidth: 80,
		height: '100%',
		'& .MuiSelect-select': {
			padding: '16px 8px',
			color: theme.palette.primary.main,
			backgroundColor: alpha(theme.palette.background.paper, 0.1),
			borderRadius: '0 8px 8px 0',
			border: 'none',
		},
		'& .MuiOutlinedInput-notchedOutline': {
			border: 'none',
		},
		'&:hover .MuiOutlinedInput-notchedOutline': {
			border: 'none',
		},
		'&.Mui-focused .MuiOutlinedInput-notchedOutline': {
			border: 'none',
		},
		'& .MuiSelect-icon': {
			color: theme.palette.primary.contrastText,
		},
	};
	
	return (
		<Box sx={[defaultSx, ...(Array.isArray(sx) ? sx : [sx])]}>
			<Box sx={{ display: 'flex', alignItems: 'stretch', height: '56px' }}>
				<Controller
					name={filenameField}
					control={control}
					defaultValue={placeholder}
					render={({ field, fieldState: {error} }) => (
						<TextField
							{...field}
							label={label}
							placeholder={placeholder}
							variant="filled"
							error={!!error}
							helperText={error?.message}
							sx={{
								flex: 1,
								'& .MuiFilledInput-root': {
									backgroundColor: 'transparent !important',
									borderRadius: '8px 0 0 8px',
									'&:before': { borderBottom: 'none' },
									'&:after': { borderBottom: 'none' },
									'&:hover': {
										backgroundColor: 'transparent !important',
										'&:before': { borderBottom: 'none' },
									},
									'&.Mui-focused': {
										backgroundColor: 'transparent !important',
									},
								},
							}}
						/>
					)}
				/>
				<Controller
					name={extensionField}
					control={control}
					defaultValue={extensions[0]}
					render={({ field, fieldState: {error} }) => (
						<Select
							{...field}
							variant="outlined"
							error={!!error}
							sx={selectSx}
							>
							{extensions.map((ext) => (
								<MenuItem 
								key={ext} 
								value={ext}
								sx={{ 
									color: theme.palette.primary.main,
									backgroundColor: theme.palette.background.paper,
									'&:hover': {
										backgroundColor: alpha(theme.palette.primary.main, 0.1),
									},
									'&.Mui-selected': {
										backgroundColor: alpha(theme.palette.primary.main, 0.2),
										'&:hover': {
											backgroundColor: alpha(theme.palette.primary.main, 0.3),
										},
									},
								}}
								>
								{ext}
								</MenuItem>
							))}
						</Select>
					)}
				/>
			</Box>
		</Box>
	);
}
