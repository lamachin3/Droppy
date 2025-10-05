import type { ReactNode } from "react";
import { alpha, Select, useTheme, type SelectProps } from "@mui/material";


interface FormSelectProps extends Omit<SelectProps, 'onChange'> {
	children?: ReactNode;
}

export default function FormSelect({ children, ...props }: FormSelectProps) {
	const theme = useTheme();
	
	return (
		<Select
			variant="outlined"
			fullWidth
			sx={{
				backgroundColor: alpha(theme.palette.background.default, 0.6),
				borderRadius: 2,
				"& .MuiSelect-select": {
					backgroundColor: 'transparent',
					'&:hover': {
						borderColor: alpha(theme.palette.primary.main, 0.8),
					},
					'&.Mui-focused': {
						borderColor: alpha(theme.palette.primary.main, 0.8),
					},
				},
				"& .MuiSelect-icon": {
					fill: "white !important",
				},
				"&:hover .MuiSelect-icon": {
					fill: theme.palette.primary.main,
				},
				"& .MuiOutlinedInput-notchedOutline": {
					border: '0.5px solid',
					borderColor: alpha(theme.palette.grey[600], 0.6),
					borderRadius: 2,
				},
				'&:focus-within': {
					borderColor: alpha(theme.palette.primary.main, 0.8),
				},
			}}
			{...props}
			>
			{children}
		</Select>
	);
}