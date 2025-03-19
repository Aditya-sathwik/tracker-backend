import { ApiError } from '../utils/apierror.js';

app.use((err, req, res, next) => {
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: err.success,
      message: err.message,
      errors: err.errors,
    });
  }

  // Fallback for unexpected errors
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
  });
});
