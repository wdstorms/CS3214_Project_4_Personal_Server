/*
 * This HOC can be used to wrap components so that if they are rendered without authentication,
 * they redirect to '/login' first and then come back.
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router';
import { useSelector } from 'react-redux';
import { isLoaded } from '../util/loadingObject';

export default function RequireAuthentication(Component) {
  const wrapper = props => {
    const location = useLocation();
    const user = useSelector(state => state.auth);
    if (isLoaded(user)) {
      return <Component {...props} />;
    } else {
      return (
        <Navigate
            to={`/login`}
            state = {{
                from: location
            }}
        />
      );
    }
  };

  return wrapper;
}
