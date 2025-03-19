const asyncHandler = (fn) => {
    return async (req, res, next) => {
      try {
        await fn(req, res, next);
      } catch (error) {
        // Convert error to JSON
        const errorResponse = {
          status: error?.status || 500, 
          message: error?.message || 'Internal Server Error',
        };
  
        res.status(errorResponse.status).json(errorResponse); 
      }
    };
  };
  
  export {asyncHandler};