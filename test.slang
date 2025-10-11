#ifndef __CUSTOM31_INC
#define __CUSTOM31_INC

[Differentiable]
public float3 cart_to_cyl(uniform float3 xyz) {
  float radius = length(xyz.xy);
  float theta = atan2(xyz.y, xyz.x);
  return float3(radius, theta, xyz.z);
}

public float3x3 cart_to_cyl_jacobian(uniform float3 xyz, uniform float3 n) {
  DifferentialPair<float3> dp_x = diffPair(xyz, float3(1, 0, 0));
  DifferentialPair<float3> dp_y = diffPair(xyz, float3(0, 1, 0));
  DifferentialPair<float3> dp_z = diffPair(xyz, float3(0, 0, 1));

  DifferentialPair<float3> dp_x_out = fwd_diff(cart_to_cyl)(dp_x);
  DifferentialPair<float3> dp_y_out = fwd_diff(cart_to_cyl)(dp_y);
  DifferentialPair<float3> dp_z_out = fwd_diff(cart_to_cyl)(dp_z);

  return float3x3(dp_x_out.d, dp_y_out.d, dp_z_out.d);
}

#endif  // __CUSTOM31_INC

