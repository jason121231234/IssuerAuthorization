# Native Blind Attribute-Based Signature: Algorithm Specification

This specification accompanies the [extended security analysis](security-proofs-rewrite.md) and the reviewer implementation. It fixes the equations used by that analysis. The construction combines Jutla–Roy attribute certification, a three-coordinate FHS signature on equivalence classes, and complete Groth–Sahai (GS) proofs. Policies are public monotone policies, including AND/OR combinations; keys are attribute keys, not policy-specific keys.

## 1. Parameters and notation

Use a Type-III pairing $e:\mathbb G_1\times\mathbb G_2\to\mathbb G_T$ over groups of prime order $p$, with generators $g_1,g_2$. Scalars are in $\mathbb F_p$. Publish independent Pedersen bases $H_1,\ldots,H_L\in\mathbb G_1\setminus\{1\}$, with their generation exponents erased and no corresponding second-group bases. A supported field format $\mathsf{sid}$ fixes the content encoding and ordered bases.

The authenticated parameter record binds the pairing, RA verification key, GS keys, encodings, and field formats through $\mathsf{pp\text{-}id}$. The VDR retains authenticated records for earlier authorization periods.

For an issuer, let

$$
\boldsymbol x=(x_1,x_2,x_3)\in(\mathbb F_p^*)^3,
\qquad \boldsymbol X=(g_2^{x_1},g_2^{x_2},g_2^{x_3}).
$$

The RA registers distinct complete vectors. Attribute encoding binds authority, type, value, and period: $a_{i,\tau}=\mathsf{EncodeAttr}(\mathsf{RA},\mathsf{type}_i,\mathsf{value}_i,\tau)$ and $A_{i,\tau}=g_2^{a_{i,\tau}}$. The signing context is

$$
j=\mathsf{Encode}(\mathcal P,\tau,d,\mathsf{sid})\in\mathbb F_p^*,
\qquad J=g_1^j,\qquad d\in\{\mathsf{VC},\mathsf{VP}\}.
$$

Context encoding is deterministic and collision resistant; it is not a hash-to-group replacement for the signed commitment. A normalized signature signs $(C,g_1,J)$ directly.

## 2. RA setup and attribute certification

Generate the exchanged-group JR key and its QA parameters using the component's joint key-generation distribution. Write its public elements as $Q_1,\ldots,Q_8,Q_0,Q_A\in\mathbb G_1$. These elements are not independently chosen substitutes for the component distribution.

For each approved attribute, issue a JR certificate

$$
\mathsf{cert}_{i,\tau}=(R_i,\widehat R_i,S_i,G_i,T_i,P_i),
$$

where $R_i,\widehat R_i,S_i,G_i,P_i\in\mathbb G_2$ and $T_i\in\mathbb G_1$, on the four-coordinate message $(X_1,X_2,X_3,A_{i,\tau})$. Verification is

$$
\prod_{j=1}^{3}e(Q_j,X_j)\,
e(Q_4^{a_{i,\tau}}Q_0,g_2)\,
e(Q_5,R_i)e(Q_6,\widehat R_i)e(Q_7,S_i)e(Q_8,G_i)
=e(Q_A,P_i),
$$

$$
e(T_i,R_i)=e(g_1,S_i).
$$

The issuer reuses these certificates across satisfied policies. Permission certificates are renewed for their authorization period, and every certified label is bound to that period.

For complete GS proofs, generate

$$
\boldsymbol v_1=(g_1^\xi,g_1),\quad
\boldsymbol w_1=\boldsymbol v_1^\rho,\quad
\boldsymbol v_2=(g_2^\zeta,g_2),\quad
\boldsymbol w_2=\boldsymbol v_2^\sigma,
$$

with $\xi,\zeta\in\mathbb F_p^*$ and $\rho,\sigma\in\mathbb F_p$. Erase setup secrets after publishing the authenticated record. Hidden elements are committed as

$$
\mathsf{Com}_1(L;r,t)=(1,L)\boldsymbol v_1^r\boldsymbol w_1^t,
\qquad
\mathsf{Com}_2(R;r,t)=(1,R)\boldsymbol v_2^r\boldsymbol w_2^t.
$$

## 3. Policy authorization relation

Derive a labeled matrix $M\in\mathbb F_p^{k\times\ell}$ from the public monotone policy. A satisfying subset reconstructs $\boldsymbol e_1$. The public policy determines all row positions and the complete proof layout, including unselected rows.

Choose $b_i\in\{0,1\}$ and weights $v_i$ such that

$$
v_i(1-b_i)=0,\qquad \sum_i v_iM_{i,t}=\delta_{t,1}.
$$

For selected rows use the corresponding certificate; for other rows use identities. Set

$$
B_{1,i}=g_1^{b_i},\quad B_{2,i}=g_2^{b_i},\quad
V_i=g_1^{v_i},\quad W_{i,j}=X_j^{b_i}.
$$

The GS authorization relation contains, for every row,

$$
e(g_1,W_{i,j})=e(B_{1,i},X_j)\quad(j=1,2,3),
$$

$$
\prod_{j=1}^{3}e(Q_j,W_{i,j})\,
e(Q_4^{a_{i,\tau}}Q_0,B_{2,i})\,
e(Q_5,R_i)e(Q_6,\widehat R_i)e(Q_7,S_i)e(Q_8,G_i)
=e(Q_A,P_i),
$$

$$
e(T_i,R_i)=e(g_1,S_i),\quad
e(B_{1,i},g_2)=e(g_1,B_{2,i}),
$$

$$
e(B_{1,i},g_2/B_{2,i})=1,\qquad
e(V_i,g_2/B_{2,i})=1,
$$

and one reconstruction equation per column,

$$
\prod_i e(V_i,g_2)^{M_{i,t}}=e(g_1,g_2)^{\delta_{t,1}}.
$$

All key-association and signature equations share the same commitments to $X_1,X_2,X_3$. Every occurrence of a hidden variable shares its commitment. Separate variables have separate masks even if their group values happen to coincide.

## 4. VC issuance

After qualification assessment, the issuer encodes $\boldsymbol m=(m_1,\ldots,m_L)$, samples $r_0$, and computes

$$
C_0=g_1^{r_0}\prod_{h=1}^L H_h^{m_h}.
$$

The VC policy includes the permission requirement, issuer identity, and time requirement. For the resulting $J_{\rm VC}$, sample $y\in\mathbb F_p^*$ and set

$$
Z=(C_0^{x_1}g_1^{x_2}J_{\rm VC}^{x_3})^y,
\quad Y=g_1^{1/y},\quad \gamma=g_2^{1/y}.
$$

Combine the authorization equations with

$$
e(C_0,X_1)e(g_1,X_2)e(J_{\rm VC},X_3)=e(Z,\gamma),
\qquad e(Y,g_2)=e(g_1,\gamma).
$$

Produce complete GS commitments and proofs for these equations. Publish only $\eta=(\gamma,\mathcal C,\Pi)$, not the hidden raw signature or key. Return the VC and its opening $(r_0,\boldsymbol m)$ to the holder. The holder verifies the complete VC and recomputes its commitment. Message coordinates and $\gamma$ must be nonidentity; $Z$ need not be.

## 5. Blind request and response

The verifier chooses the required policy. Conversion may be prepared in advance for a known requirement. Under the current service interface, the target retains the source permission condition and period and omits its identity condition. This interface does not restrict the underlying policy language to fixed AND templates.

The holder chooses a fresh $\Delta$ with $C_1=C_0g_1^\Delta\notin\{1,C_0\}$, and $s\in\mathbb F_p^*$. Put

$$
t=s\Delta,\quad U=C_1^s=C_0^s g_1^t,
\quad V=g_1^s,\quad W=V^{j_{\rm VP}}.
$$

The request proof establishes knowledge of $(r_0,\boldsymbol m,s,t)$. Its three Schnorr first messages use fresh masks:

$$
A_0=g_1^{a_r}\prod_hH_h^{a_h},\quad
A_1=g_1^{a_s},\quad A_2=C_0^{a_s}g_1^{a_t}.
$$

The Fiat–Shamir challenge binds the source VC, target policy, time, purpose, format, parameter identifier, $(U,V,W)$, and all first messages. Responses are $z_r=a_r+cr_0$, $z_h=a_h+cm_h$, $z_s=a_s+cs$, and $z_t=a_t+ct$. Verify

$$
g_1^{z_r}\prod_hH_h^{z_h}=A_0C_0^c,\quad
g_1^{z_s}=A_1V^c,\quad C_0^{z_s}g_1^{z_t}=A_2U^c,
\quad W=V^{j_{\rm VP}}.
$$

The issuer checks its source record and source VC, the permitted policy/time/format transition, and this proof. It signs $(U,V,W)$ with fresh $y$ using

$$
Z_0=(U^{x_1}V^{x_2}W^{x_3})^y,
\quad Y_0=g_1^{1/y},\quad \gamma_0=g_2^{1/y},
$$

and returns a complete GS proof of target authorization and both signature equations. The holder verifies that entire response against its exact request and target parameters before any unblinding.

## 6. Unblinding and complete refresh

Set $\mu=s^{-1}$ and choose fresh $\psi\in\mathbb F_p^*$. Transform

$$
Z'=Z_0^{\psi\mu},\quad Y'=Y_0^{\psi^{-1}},\quad
\gamma'=\gamma_0^{\psi^{-1}}.
$$

Scale the commitment to $Z_0$ by $\psi\mu$, and the commitment to $Y_0$ by $\psi^{-1}$. Replace the public message by $(U^\mu,V^\mu,W^\mu)=(C_1,g_1,J_{\rm VP})$. Scale message proof vectors by $\mu$, consistency proof vectors by $\psi^{-1}$, and retain the authorization equations. The fixed public generator in the consistency equation keeps its prescribed public position.

For each hidden first-group variable choose fresh $(\lambda_q,\nu_q)$, and for each hidden second-group variable choose fresh $(\rho_t,\sigma_t)$. Update

$$
\boldsymbol c'_q=\boldsymbol c_q\boldsymbol v_1^{\lambda_q}\boldsymbol w_1^{\nu_q},\qquad
\boldsymbol d'_t=\boldsymbol d_t\boldsymbol v_2^{\rho_t}\boldsymbol w_2^{\sigma_t}.
$$

For a PPE coefficient matrix $\Gamma$, correct its four complete proof vectors:

$$
\boldsymbol\pi'_1=\boldsymbol\pi_1\prod_t(\boldsymbol d'_t)^{\sum_q\lambda_q\Gamma_{qt}},\quad
\boldsymbol\pi'_2=\boldsymbol\pi_2\prod_t(\boldsymbol d'_t)^{\sum_q\nu_q\Gamma_{qt}},
$$

$$
\boldsymbol\theta'_1=\boldsymbol\theta_1\prod_q\boldsymbol c_q^{\sum_t\Gamma_{qt}\rho_t},\quad
\boldsymbol\theta'_2=\boldsymbol\theta_2\prod_q\boldsymbol c_q^{\sum_t\Gamma_{qt}\sigma_t}.
$$

Use the new $\boldsymbol d'_t$ and previous $\boldsymbol c_q$ in exactly this order. Public variable positions have zero increments. Independently sample $(\alpha,\beta,\chi,\delta)$ for each equation and set

$$
\boldsymbol\pi''_1=\boldsymbol\pi'_1\boldsymbol v_2^\alpha\boldsymbol w_2^\beta,\quad
\boldsymbol\pi''_2=\boldsymbol\pi'_2\boldsymbol v_2^\chi\boldsymbol w_2^\delta,
$$

$$
\boldsymbol\theta''_1=\boldsymbol\theta'_1\boldsymbol v_1^{-\alpha}\boldsymbol w_1^{-\chi},\quad
\boldsymbol\theta''_2=\boldsymbol\theta'_2\boldsymbol v_1^{-\beta}\boldsymbol w_1^{-\delta}.
$$

The four independent equation masks cover the complete proof kernel. Reuse the refreshed commitment at every occurrence of one variable. No witness opening is needed for refresh.

## 7. Presentation

The holder now has $r_1=r_0+\Delta$ and the unchanged vector $\boldsymbol m$. For the hidden-vector workflow it proves

$$
C_1=g_1^{r_1}\prod_hH_h^{m_h}.
$$

Its Schnorr first message is $B=g_1^{a_r}\prod_hH_h^{a_h}$. Bind the final ABS bytes, $C_1$, policy, time, purpose, format, parameter identifier, verifier nonce, and $B$ into the Fiat–Shamir challenge. Verify the resulting opening equation and the complete ABS under the verifier's exact public requirements.

The mathematical selective-disclosure extension reveals coordinates $D$ and proves the residual relation

$$
C_1\prod_{h\in D}H_h^{-m_h}
=g_1^{r_1}\prod_{h\notin D}H_h^{m_h},
$$

binding the ordered disclosed coordinates and values into the same challenge. The released reviewer measurements use $D=\varnothing$; they do not benchmark this extension.

Preparing the normalized, refreshed VP does not require a presentation nonce. The final opening proof binds the later nonce. The measured implementation exposes this separation without removing the mandatory response check.

## 8. Component references

- [Jutla–Roy attribute certification](https://eprint.iacr.org/2017/025.pdf), full SPS/QA generation and verification.
- [FHS equivalence-class signatures](https://eprint.iacr.org/2014/944.pdf), Scheme 1 and its Type-III generic-group security theorem.
- [Complete GS proofs](https://eprint.iacr.org/2013/662.pdf), extraction/simulation commitment keys and complete PPE proofs.

The [proof checklist](security-proof-checklist.md) records the models, reduction interfaces, and implementation correspondence for this composition.
