import { ReactElement } from 'react';

interface PublicRouteProps {
  element: ReactElement;
}

/**
 * A simple wrapper that renders its children without any authentication checks.
 * Use this for public routes that should be accessible to everyone.
 */
export function PublicRoute({ element }: PublicRouteProps) {
  // Simply render the provided element without any authentication checks
  return element;
}

export default PublicRoute;
