# Extended Security Analysis

This analysis accompanies the native blind attribute-based signature (ABS) used in *Privacy-Preserving Verification of Fine-Grained Issuer Authorization for AI Agent Credentials*. The algorithms are given in [Algorithm Specification](algorithm-specification.md). It expands the authorization/one-more and issuer-privacy/unlinkability arguments in the conference paper, and additionally states correctness, content consistency, opening knowledge, and selective-disclosure privacy. The statements below specify their adversarial interfaces separately.

The conference theorem on authorization and one-more unforgeability is expanded by Lemma 2 and Theorems 2–3. Its theorem on issuer privacy and unlinkability is expanded by Lemma 1 and Theorems 1 and 7. Definitions below include the complete public presentation requirements: the parameter set, policy, time, purpose, field format, and any disclosed coordinate indices and values. The companion [claim map](security-claim-map.md) identifies the corresponding games and bounds. This supplement accompanies the manuscript and implementation at project revision `29ad482`; publication of this document does not change their algorithms.

## 1. Parameters, relations, and acceptance

Let $e:\mathbb G_1\times\mathbb G_2\to\mathbb G_T$ be a nondegenerate Type-III pairing over groups of prime order $p$, with generators $g_1,g_2$. Write $\mathbb G_i^*=\mathbb G_i\setminus\{1\}$. All games use one trusted, authenticated parameter set $\mathsf{pp}$. The parameter identifier $\mathsf{pp\text{-}id}$ binds the groups, RA verification key, GS commitment keys, supported field formats, encodings, and independent Pedersen bases. The setup secrets used to extract GS commitments or generate Pedersen bases are unavailable to protocol participants.

An issuer has $\boldsymbol x=(x_1,x_2,x_3)\in(\mathbb F_p^*)^3$ and $\boldsymbol X=(g_2^{x_1},g_2^{x_2},g_2^{x_3})$. The RA registers distinct complete vectors. For attribute $a$ and time value $\tau$, it issues a JR certificate on $(X_1,X_2,X_3,A_{a,\tau})$, where $A_{a,\tau}=g_2^{\mathsf{EncodeAttr}(a,\tau)}$. The encoding includes the authority, attribute type and value, and time value. Let $S_\tau(\boldsymbol X)$ be the cumulative set certified to this complete vector for that period. The policy is satisfied by one such set, rather than by a union of sets belonging to different vectors.

A public monotone policy has a deterministically derived labeled matrix $M\in\mathbb F_p^{k\times\ell}$. A satisfying set of rows spans $\boldsymbol e_1$. The public policy fixes all row positions and the complete proof layout, including unused rows. The policy-row count $k$, matrix dimension $\ell$, and content length $L$ are separate quantities.

For field format $\mathsf{sid}$, the issuer commits to the encoded content vector as

$$
C_0=g_1^{r_0}\prod_{h=1}^{L}H_h^{m_h},\qquad
\boldsymbol m\in\mathbb F_p^L.
\tag{1}
$$

The bases $H_h\in\mathbb G_1^*$ are generated independently, with their discrete-logarithm relations erased; no same-exponent partners for them are released in $\mathbb G_2$. Public context encoding gives

$$
j=\mathsf{Encode}(\mathcal P,\tau,d,\mathsf{sid})\in\mathbb F_p^*,
\qquad J=g_1^j,
\qquad \boldsymbol N(T)=(C,g_1,J),
\tag{2}
$$

where $T=(C,\mathcal P,\tau,d,\mathsf{sid})$. VC and VP purposes are separated in this encoding. Each message coordinate must be nonidentity; the hidden signature component $Z$ may be the identity.

The raw FHS signature is

$$
Z=(C^{x_1}g_1^{x_2}J^{x_3})^y,\quad
Y=g_1^{1/y},\quad \gamma=g_2^{1/y},\qquad y\in\mathbb F_p^*.
\tag{3}
$$

The ABS publishes $\eta=(\gamma,\mathcal C,\Pi)$, where $\mathcal C$ commits to the hidden key, signature, selection variables, and attribute certificates, and $\Pi$ proves every authorization and message equation. The equations share one commitment for each occurrence of the same hidden variable. Distinct variable positions use independent masks even when their group values coincide. In particular,

$$
e(C,X_1)e(g_1,X_2)e(J,X_3)=e(Z,\gamma),\qquad
e(Y,g_2)=e(g_1,\gamma).
\tag{4}
$$

An accepted ABS has the prescribed layout and $\gamma\in\mathbb G_2^*$, and all its complete GS equations verify. Acceptance uses authenticated parameters and valid elements in the specified groups. GS extraction below recovers group witnesses, not their discrete logarithms. The complete PPE instantiation supplies this property through its extraction setup [3].

In a conversion, an honest holder chooses a fresh target $C_1=C_0g_1^\Delta$ uniformly in $\mathbb G_1\setminus\{1,C_0\}$, and independently chooses $s\in\mathbb F_p^*$. It submits

$$
U=C_1^s=C_0^s g_1^t,\quad V=g_1^s,\quad W=V^j,
\qquad t=s\Delta.
\tag{5}
$$

The request proves knowledge of $(r_0,\boldsymbol m,s,t)$ for (1) and (5). The issuer sees the source VC and may retain its content, opening, and issuance record; the request does not contain $C_1$, $\Delta$, or an element $g_2^s$. Honest conversion responses use the source-checked interface and the approved policy/time/format transition. Before unblinding, the holder verifies the entire response on its exact $(U,V,W)$ and target parameters.

Let $\mu=s^{-1}$ and $\psi\in\mathbb F_p^*$ be fresh. The holder changes the hidden signature and its commitments according to

$$
Z'=Z_0^{\psi\mu},\qquad Y'=Y_0^{\psi^{-1}},\qquad
\gamma'=\gamma_0^{\psi^{-1}}.
\tag{6}
$$

It scales all message-equation proof vectors by $\mu$, all consistency-equation proof vectors by $\psi^{-1}$, then refreshes every hidden commitment and every complete equation proof. The fixed generator in the consistency equation retains its own public position. Finally it proves an opening of $C_1$. The presentation challenge binds $\mathsf{pp\text{-}id}$, the entire final $\eta'$, $C_1$, policy, time, purpose, format, verifier nonce, and first proof message. If fields are disclosed, their ordered indices and values are bound as well. The final VP contains no source VC or issuance-session identifier.

**Proposition 1 (Correctness).** Honest VC issuance and completed VP conversion satisfy the authorization, signature, and opening equations.

**Proof.** Selected certified rows reconstruct $\boldsymbol e_1$. Equation (3) satisfies (4) by bilinearity. Equations (5)–(6) give a valid signature on $(C_1,g_1,J)$, and the message and consistency verification matrices scale by $\mu$ and $\psi^{-1}$, respectively. The refresh identities in Lemma 1 preserve those matrices. Finally, $C_1=g_1^{r_0+\Delta}\prod_hH_h^{m_h}$, providing the holder's final opening with unchanged content. $\square$

## 2. Complete refresh and blindness

**Lemma 1 (Distribution of complete refreshed proofs).** In the GS simulation setup, for any complete response accepted on the exact request, the holder's normalization and independent refresh produce a final signature-proof distribution determined only by the final public statement. It is independent of the response's original hidden witnesses, commitment masks, and proof values.

**Proof.** Work temporarily in exponent notation to analyze distributions. The simulation commitment vectors are

$$
\boldsymbol v_1=(g_1^\xi,g_1),\quad
\boldsymbol w_1=(g_1^{\xi\rho},g_1^{\rho-1}),\qquad
\boldsymbol v_2=(g_2^\zeta,g_2),\quad
\boldsymbol w_2=(g_2^{\zeta\sigma},g_2^{\sigma-1}).
\tag{7}
$$

Let $A$ have the first-group vectors as columns, and $B$ have the second-group vectors as rows. Their determinants are $-\xi$ and $-\zeta$, both nonzero. An independent uniform pair of mask increments therefore makes each hidden commitment uniform in its two-dimensional group space, regardless of its starting value. Shared occurrences retain a single refreshed commitment; different variable positions are refreshed independently.

For one equation, write its commitment matrices as $\mathsf C,\mathsf D$, its public coefficient matrix as $\Gamma$, and the complete proof matrices as $P$ and $T$. The four matrix verification constraints are

$$
\mathsf C\Gamma\mathsf D=AP+TB.
\tag{8}
$$

The prescribed correction is valid because

$$
(\mathsf C+\Delta\mathsf C)\Gamma(\mathsf D+\Delta\mathsf D)
-\mathsf C\Gamma\mathsf D
=\Delta\mathsf C\Gamma(\mathsf D+\Delta\mathsf D)
+\mathsf C\Gamma\Delta\mathsf D.
\tag{9}
$$

Thus the first correction uses the new second-group commitments, and the second uses the previous first-group commitments. Public positions have zero increments. This identity applies to every accepted input matrix proof, including a proof chosen by a malicious issuer.

Fix the refreshed commitments. The map $(P,T)\mapsto AP+TB$ from eight scalar coordinates to four coordinates is surjective: for any right-hand matrix $D_0$, take $P=A^{-1}D_0$ and $T=0$. Its kernel consequently has dimension four. For

$$
K=\begin{pmatrix}\alpha&\beta\\\chi&\delta\end{pmatrix},\qquad
\Delta P=KB,\qquad \Delta T=-AK,
\tag{10}
$$

the verification contribution is $AKB-AKB=0$. Because $B$ is invertible, this four-dimensional map is injective and hence covers the entire kernel. Four fresh uniform masks per equation make the proof uniform over all accepted proofs for its refreshed commitments. Independent masks across equations give the joint conditional distribution, despite shared commitment variables.

Normalization preserves matrix verification: the message matrix scales by $\mu$, and the consistency matrix by $\psi^{-1}$. Moreover, for every accepted nonidentity $\gamma_0$, $\gamma_0^{\psi^{-1}}$ is uniform in $\mathbb G_2^*$, conditionally on the issuer's entire view. Conditional on that new value and the final public representative, the commitment and proof distributions just derived depend only on that statement. This proves the claim for arbitrary accepted responses. $\square$

**Definition 1 (Request hiding and completed-session unlinkability).** For request hiding, a malicious issuer receives a valid source VC, and may know its opening and its own complete secret state. The challenger generates two fresh target commitments for that source by the prescribed holder randomization, reveals the two commitments without their openings, and supplies a request for one uniformly selected target under a common target policy, time, purpose, and format. The advantage is $\left|\Pr[b'=b]-1/2\right|$.

For completed-session unlinkability, the adversary controls the issuers in two conversions and retains their keys, certificates, source VCs, contents, openings, records, randomness, and messages. Both issuers qualify for the same final public policy, time, purpose, format, and parameter set. They may use different hidden attribute supports. Each holder generates its target and request honestly; the adversary may return any response. Each holder accepts only after its exact complete-response verification, then independently normalizes and refreshes. If either conversion fails, the experiment returns one common failure result. Otherwise a fresh bit permutes the two final VPs. Verifier nonces are independently generated at presentation time. If fields are disclosed, both VPs disclose the same indices and values. With $\mathsf{Complete}$ denoting two completions, define

$$
\mathsf{Adv}_{\rm link}
=\left|\Pr[\mathsf{Complete}\land b'=b]
-\tfrac12\Pr[\mathsf{Complete}]\right|.
\tag{11}
$$

The game thus measures the association advantage over completed executions without renormalizing by a potentially small completion probability.

Let $\epsilon_{\rm CRS}$ bound the complete real/simulation setup replacement, $\epsilon_{\rm DDH,1}$ bound a DDH replacement in $\mathbb G_1$, and $\delta_{\rm ROM}=q_{\rm sim}Q_H/p+\delta_{\rm map}$. Here $Q_H$ bounds all occupied entries in the common random-oracle cache before programming, including honest queries and prior programmed entries; $q_{\rm sim}$ counts simulated proofs. The mapping term covers the field-challenge implementation.

**Theorem 1 (Blindness).** Under SXDH and random-oracle zero knowledge of the request and opening proofs, the two games of Definition 1 have advantage at most

$$
\epsilon_{\rm CRS}+2\epsilon_{\rm DDH,1}
+\delta_{\rm ROM}+\delta_{\rm target},
\tag{12}
$$

where one conservative domain budget is $\delta_{\rm target}\le10/p$. For unconditioned DDH challenges, the chosen commitment-key distributions admit

$$
\epsilon_{\rm CRS}\le
2\epsilon_{\rm DDH,1}+2\epsilon_{\rm DDH,2}+4/p.
\tag{13}
$$

**Proof.** First replace the extraction setup with the simulation setup. In either group, the real second commitment vector and its simulation counterpart each become the same independent vector after one DDH replacement. Repeating this for both groups gives (13). The authenticated parameter identifier and records are generated consistently with the selected setup in each game.

Next simulate the request and final opening proofs. For a request, choose the field challenge and responses, and compute its first messages as

$$
A_0=g_1^{z_r}\prod_hH_h^{z_h}C_0^{-c},\quad
A_1=g_1^{z_s}V^{-c},\quad
A_2=C_0^{z_s}g_1^{z_t}U^{-c}.
\tag{14}
$$

Program the request oracle on the complete public transcript. For an opening, similarly set $B_0=g_1^{z_r}\prod_hH_h^{z_h}C_1^{-c}$, using the residual commitment for a disclosed presentation. A fresh first-message coordinate is uniform, so a programming conflict with an occupied cache entry has probability at most $Q_H/p$. Sum over simulated proofs. The simulations include all public bindings and can operate without the target opening or the blinding exponent.

For completed VPs, Lemma 1 now permits replacing the holder's output by a simulation of its final accepted statement, with a fresh uniform $\gamma'$. Its fixed all-row layout reveals no selected support. This replacement preserves the adversary's issuer records and arbitrary accepted response choices. It is performed before embedding an unknown DDH exponent.

Finally, for each challenge session, embed the tuple

$$
(g_1,C_1,V,U)=(g_1,g_1^a,g_1^b,g_1^{ab})
\tag{15}
$$

and replace its last element by an independent group element under DDH. Construct $W=V^j$ directly from the public $j$; the request proof is already simulated. Since $C_1$ is absent from the request transcript, all other request bindings, including the source VC, can be preserved. No source-group conversion or computation of $s=b$ is needed. Use at most two such replacements for the two challenge targets or sessions.

In the resulting game, the issuer's request/response history and its completion decisions depend on $U,V,W$ and the known sources, but not on the fresh final commitments. The simulated final ABS and opening proofs depend only on their final public statements. Those statements have symmetric distributions under the final permutation. The common failure result also contains no permutation information, making (11) zero in this last game. Excluding $1,C_0$ from the two target distributions costs at most $4/p$; coupling two unconditioned DDH tuples to the required nonidentity domains costs at most another $6/p$. The CRS domain correction is accounted for in (13). Summing the transitions gives (12). Each transition preserves computational indistinguishability, so the claims hold in the real experiment. $\square$

**Application conditions.** Fresh target commitments and private target openings are part of the honest-holder interface. The public presentation requirements, including any disclosed coordinates, are matched across compared sessions. The issuer's known source information remains part of its view throughout the proof.

## 3. Authorization and distinct-target unforgeability

The JR component is used with its full signing and QA parameter distribution [1]. Let $\epsilon_{\rm JR}$ be its EUF-CMA advantage and $\epsilon_{\rm FHS}$ the three-coordinate new-class advantage for Scheme 1 in the Type-III generic-group model [2]. Let $\epsilon_{\rm enc}$ bound collisions in attribute, context, and authenticated parameter identifiers. Let $\delta_{\rm reg}$ account for the unique-registration challenge embedding. Let $N$ bound honest issuer slots. These advantages include the reductions' complete outer group and oracle costs.

For an implementation conditioning JR setup scalars to be nonzero, let $\delta_{\rm par}$ be its statistical distance from the corresponding component distribution. The released setup conditions at most eighteen scalar draws; a conservative coupling bound is $\delta_{\rm par}\le18/p$, with an already restricted component draw contributing zero. Set $\epsilon_A=\epsilon_{\rm JR}+\epsilon_{\rm enc}+\delta_{\rm reg}+\delta_{\rm par}$. Exact component-generation distributions have $\delta_{\rm par}=0$.

**Lemma 2 (Authorization extraction).** In the extraction setup, an accepted complete ABS yields one common $\boldsymbol X$, valid JR certificates on its selected attribute/time messages, and selected rows spanning $\boldsymbol e_1$.

**Proof.** Extract a first-group commitment $(c_1,c_2)$ as $c_2c_1^{-1/\xi}$, and use the analogous second-group extraction map. Applying the maps to each verified PPE cancels the mask terms and recovers its group equation. Extract each shared variable once.

Write the extracted selection values as $B_{1,i}=g_1^{b_i}$, $B_{2,i}=g_2^{\widehat b_i}$, and $V_i=g_1^{v_i}$. Nondegeneracy of the bit and support equations gives

$$
b_i=\widehat b_i,\qquad b_i(1-b_i)=0,\qquad
v_i(1-b_i)=0.
\tag{16}
$$

Thus $b_i\in\{0,1\}$ and unselected rows have zero weight. The reconstruction equations imply $\sum_i v_iM_i=\boldsymbol e_1$. For every selected row, the three key-association equations imply $W_{i,j}=X_j$; its two certificate equations are exactly JR verification on $(X_1,X_2,X_3,A_{i,\tau})$. These rows and the message equations use the same three extracted key elements. Selected rows are identified by testing $B_{1,i}=g_1$. A linear system on their public rows recovers satisfying weights without taking discrete logarithms of $V_i$. $\square$

**Definition 2 (Core-EUF).** The adversary obtains authenticated parameters, registers controlled issuers, requests RA-approved attribute certificates and additions, corrupts honest issuers, and requests ordinary ABS signatures. The experiment maintains each complete registered vector and its cumulative $S_\tau$. An honest signing oracle responds only for a policy its issuer satisfies. The adversary wins with an accepted target $T^*$ never returned by an ordinary signing query, provided no single controlled or corrupted issuer satisfies its policy at its time value. The target includes purpose and format. An output claiming to be a VP must also meet the presentation acceptance rule.

**Theorem 2 (Core unforgeability).** In the Type-III generic-group model, with the complete GS extraction setup,

$$
\mathsf{Adv}_{\rm core}\le \epsilon_A+N\epsilon_{\rm FHS}.
\tag{17}
$$

**Proof.** First extract the winning signature by Lemma 2. If any selected certificate message was never certified, output its recovered JR certificate on that new message. This includes a certificate for an unregistered vector or an attribute certified only to another vector. The JR reduction uses the external RA signing oracle and generates all other issuer keys and the GS setup itself. It needs the returned certificate elements, not the RA secret coefficients, to make outer GS proofs.

Otherwise every selected certificate appears in the RA ledger for the same $\boldsymbol X$ and period. That issuer's cumulative attribute set satisfies the target policy. The victory condition therefore places this vector in an uncorrupted honest slot. Guess its registration slot uniformly among $N$, and place the external FHS public key there. Generate other issuer keys, the RA key, and the extraction setup locally. The RA can sign attribute messages containing the external group vector without knowing its exponents. Likewise, GS proving uses the group witnesses $\boldsymbol X$, the certificates, and the raw $Z,Y,\gamma$ returned by the FHS oracle. On a corruption query for the guessed slot, abort; when the guess matches the uncorrupted winning vector, this abort does not arise. Duplicate-key rejection is handled by the same registration ledger, with any distribution discrepancy charged to $\delta_{\rm reg}$.

For normalized representatives,

$$
(C',g_1,g_1^{j'})=(C,g_1,g_1^j)^a
\quad\Longrightarrow\quad a=1,\ C'=C,\ j'=j.
\tag{18}
$$

The fixed second coordinate forces the scale to one. Outside encoding collisions, equality of $j$ then fixes policy, time, purpose, and format. A fresh target therefore belongs to an unqueried FHS class under the extracted honest key. Output the extracted $(Z,Y,\gamma)$ as its raw forgery. The guessed slot succeeds with probability at least $1/N$. All outer operations, including certificate generation, proof generation, extraction, and pairings, are included in the three generic-group oracle budgets. Combining the JR and FHS branches and the stated distribution events proves (17). $\square$

**Definition 3 (Blind one-more).** The adversary has the registration, certification, and corruption interfaces of Definition 2, together with ordinary VC-signing and approved VP-signing interfaces. Let $q_{\rm VP}$ count every actual VP signature response, ordinary or blind, including repeated requests and responses later abandoned by the holder. A rejected request returning no signature adds no response. The adversary wins by outputting more than $q_{\rm VP}$ pairwise distinct accepted targets with purpose VP, each outside the complete authorization of every controlled or corrupted issuer. Different signature bytes, satisfying supports, or verifier nonces for one target are counted once. Let $L_{\rm out,max}$ bound the number of distinct outputs.

**Theorem 3 (Distinct-target one-more unforgeability).** Under the assumptions of Theorem 2,

$$
\mathsf{Adv}_{\rm OM}\le
\epsilon_A+NL_{\rm out,max}\epsilon_{\rm FHS}.
\tag{19}
$$

**Proof.** Extract all accepted outputs and use the JR classification of Theorem 2. In the absence of a new JR message, every output key is an uncorrupted qualified issuer. Simulate a blind response with exactly one FHS signing query on $(U,V,W)$, and create its outer proofs from the returned group witnesses. The request is checked through the actual interface. The simulator needs neither its scalar witness nor a second signing query for the normalized representative. An ordinary VP response also consumes exactly one signing query.

Since $V\ne1$ and $W=V^j$, each blind representative has exactly one normalized representative with second coordinate $g_1$. Equation (18) makes distinct targets distinct normalized classes. Their extracted keys consequently give at least $L_{\rm out}$ distinct key/class pairs, whereas $q_{\rm VP}$ responses cover at most that many pairs. Ordinary VC queries cannot cover VP classes because their purpose encodings differ. If $L_{\rm out}>q_{\rm VP}$, at least one output is unqueried under its extracted key. Guess its honest slot and output position, losing at most $NL_{\rm out,max}$, and submit its raw signature to the FHS game. The underlying experiment tests whether its class was queried; the reduction does not need to identify a blind representative's discrete-logarithmic normalization factor. Add the JR and distribution events to obtain (19). $\square$

## 4. Source-content consistency and opening knowledge

**Definition 4 (Source-checked content experiment).** The experiment records legitimate source VCs with explicit openings $(r_0,\boldsymbol m_0)$. Content scalars and source randomness do not use erased setup exponents. Every honest VP response is issued only after exact source-record, permitted-transition, and request-proof checks. VP-signing access in this experiment is through this interface. Controlled issuers may be registered or corrupted, subject to no single controlled issuer satisfying the final target policy. Let $\mathsf{Eligible}_{\rm content}$ denote these public-policy and interface conditions.

An adversary outputs an accepted VP and an explicit opening $(r^*,\boldsymbol m^*)$, supplied to the experiment. It wins if that opening recomputes its commitment, but no actual VP response with matching policy, time, purpose, and format has a recorded source vector equal to $\boldsymbol m^*$. Source identifiers and openings are experiment records, not extra presentation fields.

Let $Q_{\rm req}$ count distinct request-challenge queries, and $u_{\rm req}$ bound unqueried request-challenge attempts. Let $B_h$ bound the content analysis's nonidentity polynomial comparisons over all three handle tables, verification relations, and output-to-response class comparisons. Define

$$
\beta=\epsilon_A+N\epsilon_{\rm FHS}
+\frac{2Q_{\rm req}+u_{\rm req}}p
+\frac{2B_h}{p-1}+\delta_{\rm map}^{\rm req}.
\tag{20}
$$

All counts and component budgets cover the same complete content experiment. A conservative $B_h$ may enumerate all same-group handle pairs and extra verification/cross-class comparisons; this already covers the content collision budget.

**Lemma 3 (Content coefficients).** Before a nonidentity content collision, first-group exponents are affine in the independent unknown $h_h$ defined by $H_h=g_1^{h_h}$. Second-group exponents are independent of those variables. Target-group exponents are affine; the additional cross-class comparisons have degree at most two.

**Proof.** Use a symbolic oracle in the $h_h$ alone; sample other keys, setup values, and signing randomness normally and retain their numerical values inside the simulator. Random labels and oracle answers disclose no $h_h$ before a collision. Adversarial scalar choices based on those labels are therefore known coefficients independent of the $h_h$.

Initial first-group bases are affine. FHS signing, GS proving, normalization, and refresh form linear combinations or apply scalars independent of the $h_h$. JR messages and signatures are in the second group except for an independently sampled tag in the first group, so certification introduces no second-group $h_h$. Pairings multiply a first-group affine exponent by a second-group exponent independent of $h_h$, and their outputs remain in the target group. These operations preserve the asserted forms. Multiplying exponents for an analysis-only class comparison raises degree to at most two. A nonzero polynomial on independent $\mathbb F_p^*$ variables vanishes with probability at most $2/(p-1)$. Summing over $B_h$ comparisons gives the last collision term of (20). $\square$

**Theorem 4 (Vector-content consistency).** In the generic-group and random-oracle models, the success probability in Definition 4 is at most $\beta$.

**Proof.** At a request's first challenge query, write the fixed exponents of $V,A_1,U,A_2$ as affine forms with coefficient vectors $(v_0,v_h),(d_0,d_h),(u_0,u_h),(e_0,e_h)$. Request verification contains

$$
g_1^{z_s}=A_1V^c,\qquad
C_0^{z_s}g_1^{z_t}=A_2U^c.
\tag{21}
$$

For the first equation to hold symbolically, $d_h+cv_h=0$ for every $h$. If any $v_h\ne0$, at most one field challenge works. Otherwise $V=g_1^s$ with constant $s=v_0\ne0$, all $d_h=0$, and $z_s=d_0+cs$. The second equation then requires

$$
(e_h-m_{0,h}d_0)+c(u_h-m_{0,h}s)=0.
\tag{22}
$$

Unless a further challenge is guessed, $u_h=sm_{0,h}$ for every coordinate. The two challenge tests across all queried transcripts and the unqueried attempts contribute at most $(2Q_{\rm req}+u_{\rm req})/p$, plus the mapping term.

Next extract the final ABS. Outside the JR/FHS events of Theorem 2, its class belongs to an actual returned VP response under its extracted key. The second coordinate fixes the scale to $1/s$, and the third fixes $j$. Its commitment therefore has $h_h$-coefficient $u_h/s=m_{0,h}$ for that response's recorded source. A verifying explicit opening has coefficients $m_h^*$. A different coordinate would make a nonidentity $h_h$ relation vanish, already accounted for by Lemma 3. Thus outside the events in (20), the claimed vector equals one matching recorded source vector. Summing the event probabilities proves the theorem. $\square$

**Theorem 5 (Final opening knowledge).** Consider the complete, rerunnable experiment of Definition 4. Let $\epsilon=\Pr[\mathsf{Accept}_{\rm VP}\land\mathsf{Eligible}_{\rm content}]$, let $Q\ge1$ bound all new random-oracle queries in the complete run, and let $u$ bound unqueried final-challenge attempts. For ideal uniform field challenges put $\epsilon_0=\max\{0,\epsilon-u/p\}$. An offline extractor obtains a valid opening whose vector appears in the first run's matching source-response records with probability at least

$$
\max\left\{0,\epsilon_0\left(\frac{\epsilon_0}{Q}-\frac1p\right)
-(Q+1)\beta\right\}.
\tag{23}
$$

A conservative sufficient knowledge threshold is

$$
\kappa=\frac up+\frac Qp+\sqrt{Q(Q+1)\beta}.
\tag{24}
$$

**Proof.** Generate all honest keys inside this content experiment, and retain a rerunnable random tape for its group, signing, and random-oracle interfaces. Wrap the adversary to return a nonzero index only when its final VP accepts, $\mathsf{Eligible}_{\rm content}$ holds, and the final presentation challenge was queried. Return the index of the first query for that complete proof transcript. The eligibility test uses the registration, corruption, public-policy, and source-interface records, without presupposing the content equality being proved.

The general forking lemma [4] gives two accepted runs at the same selected query with different challenges $c,\widehat c$, with probability at least the nonnegative part of $\epsilon_0(\epsilon_0/Q-1/p)$. The selected query fixes the complete signature, commitment, first proof message, nonce, and public bindings. Subtracting the two opening equations gives

$$
r=\frac{z_r-\widehat z_r}{c-\widehat c},\qquad
m_h=\frac{z_h-\widehat z_h}{c-\widehat c},
\qquad C_1=g_1^r\prod_hH_h^{m_h}.
\tag{25}
$$

The content bad-event budget is unconditional. The first run is bad with probability at most $\beta$. For each fixed candidate fork index $i$, the second rerun, before filtering on the first selected index, has the marginal distribution of an ordinary complete run. Consequently $\Pr[I=i\land\mathsf{Bad}_2^{(i)}]\le\beta$. A union bound over at most $Q$ indices and the first bad event costs $(Q+1)\beta$. On the remaining successful forks, the fixed first-run commitment and signature have the source coefficients established in Theorem 4. The extracted opening therefore has the content of a matching response in that first run. Records introduced only by the second run are not added to the first ledger.

Subtracting the bad-event budget proves (23). If $\epsilon$ exceeds (24) by an inverse-polynomial margin, the bound is inverse polynomial and independent complete forks yield polynomial-budget extraction. Component and collision budgets include the full reruns. $\square$

**Application conditions.** The content and knowledge conclusions use the source-checked experiment. They establish the existence of matching source content under that interface. The final-knowledge extractor is an offline rerun of the complete content experiment; the direct FHS reductions in Theorems 2–3 simulate unknown challenge keys without this extractor. For mapped field challenges, add their statistical-distance budget to the corresponding challenge and fork bounds.

## 5. Content, selective-disclosure, and issuer privacy

**Definition 5 (Selective-disclosure content privacy).** A verifier adversary chooses two admissible vectors of the same format, a common public target policy, time, purpose and parameter set, and a disclosed index set $D$. The vectors agree on every disclosed coordinate. The challenger fixes a qualified issuer and satisfying support and runs honest issuance and conversion for the selected vector with fresh independent randomness. The challenge gives a completed anonymous VP and $\{(h,m_h):h\in D\}$ for one vector selected by a fresh bit. Its proof establishes knowledge of a residual opening

$$
C_D=C_1\prod_{h\in D}H_h^{-m_h}
=g_1^{r'}\prod_{h\notin D}H_h^{m_h}.
\tag{26}
$$

The challenge binds the ordered disclosed indices and values, final signature, format, and verifier nonce. The adversary sees the final VP and common public information, rather than the challenge source opening. Its advantage is $\left|\Pr[b'=b]-1/2\right|$. Taking $D=\varnothing$ gives hidden-vector privacy.

**Theorem 6 (Content privacy with selective disclosure).** With fresh independent commitment randomness and random-oracle zero knowledge of the residual-opening proof, Definition 5 has negligible advantage. Its bound is the opening-proof simulation error and the applicable encoding and sampling-domain errors.

**Proof.** For either vector, multiplication by $g_1^{r_0}$ makes the source commitment uniform; rejection of the identity is independent of the vector. Fresh $\Delta$ makes the target uniform outside the two specified group elements, giving the same target marginal for both vectors. The signed group representative depends on $C_1$ and the common public context, rather than on a selected opening. With an honest issuer and holder, the signature and refreshed proof distribution conditional on that representative is likewise independent of the vector.

The disclosed coordinates and values are equal in both experiments. Removing their common contributions gives the residual statement (26). Replace its proof by the transcript-bound zero-knowledge simulation, which can use fresh randomness in the coefficient of $g_1$ even when no hidden content coordinate remains. The resulting final views have the same distribution, since the target, public disclosures, and simulated proofs have the same laws. Return to the real opening proof with its simulation-error bound. $\square$

**Corollary 1 (Disclosure binding and knowledge).** A disclosed presentation's opening proof has the same special-soundness and offline knowledge argument as Theorem 5 on the residual relation, with the revealed values inserted into their fixed coordinates. Under the source-checked content interface, extracted content has a matching recorded source vector with the corresponding budgets.

**Proof.** The selected oracle query fixes $D$ and every disclosed value. Forking extracts $r'$ and the undisclosed coordinates from (26); adjoining the fixed disclosed coordinates yields an opening of $C_1$. Apply the coefficient and bad-event analysis of Theorems 4–5 to this complete vector. $\square$

**Definition 6 (Verifier's issuer and support privacy).** Fix the same complete public presentation requirements as in Definition 5. The adversary chooses two qualified issuer/support pairs, each satisfying that policy, and may know both issuers' keys and authorized attribute sets. The compared credential contents agree on disclosed coordinates. A challenge VP is generated from one pair selected by a fresh bit, and the adversary guesses the choice. Its challenge view contains the final VP, disclosures, and common public parameters. Source issuance records and source openings are not added to this verifier experiment. Its advantage is $\left|\Pr[b'=b]-1/2\right|$. At least two issuers must be consistent with the common public requirements for an identity comparison; different satisfying supports can be compared for a single issuer.

**Theorem 7 (Issuer and support privacy).** Under SXDH and random-oracle zero knowledge of the opening proof, anonymous VPs satisfy Definition 6. Participating issuers satisfy the separate completed-session experiment of Definition 1 and bound (12).

**Proof.** First replace the GS setup by its simulation distribution. Next use Lemma 1 and independent signature randomization. The final $\gamma'$ is uniform in its valid domain, hidden commitments are uniform, and each complete proof is uniform over its accepted solution set for those commitments and the final public statement. This law is independent of the chosen key and certificates. The verifier derives the same all-row layout for either support, so selecting a different satisfying branch changes no public positions or proof lengths.

Finally simulate the residual-opening proof. The public disclosures coincide, and fresh Pedersen randomness supplies the same final commitment distribution for either candidate. Hence the verifier's view in the simulation game is independent of the choice. Returning to the real setup and opening proof incurs their indistinguishability and simulation terms. The participating-issuer conclusion uses Theorem 1, whose adversarial view additionally contains the complete source and signing-session state. $\square$

**Presentation conditions.** Public policy, time, purpose, format, and disclosed coordinates are the information intentionally exposed by the presentation. The issuer/support comparison is made among candidates compatible with that information. Selective disclosure uses the mathematical partial-opening extension; the released computation and payload measurements use the hidden-vector case $D=\varnothing$.

## 6. System-level guarantees and historical verification

**Definition 7 (Accepted system objects).** A verifier fixes the required policy, time, format, and fresh presentation challenge, authenticates the common parameters, derives the policy matrix and proof layout, and verifies the complete ABS. A VP additionally verifies the transcript-bound opening proof, including any disclosures. An identified VC uses its issuer-identity condition; an anonymous VP omits that condition and retains the specified permission and time requirements. Signature freshness and response counts follow Definitions 2–3; source-content claims use Definition 4.

**Theorem 8 (Composition under the defined interfaces).** Under Definition 7 and the preceding assumptions, an accepted ABS establishes one issuer vector whose certified rows satisfy the public policy and time requirement. Unauthorized fresh targets and excess distinct VP targets obey (17) and (19). In the source-checked content experiment, valid openings obey (20), and final opening extraction obeys (23). Anonymous presentations satisfy content, issuer/support, and completed-session privacy in their respective defined views.

**Proof.** Lemma 2 connects every selected certificate and the message relation to one complete issuer vector and reconstructs the verifier's required policy. A fresh unauthorized signature is an output in Definition 2, and excess distinct VP targets are an output in Definition 3; Theorems 2–3 give their bounds. Under the source-checked interfaces, Theorems 4–5 establish recorded-content consistency and opening extraction. Theorems 1, 6, and 7 establish the three privacy comparisons with their explicitly specified disclosures and adversarial information. Each implication uses the corresponding oracle and acceptance rules, which are preserved by Definition 7. $\square$

**Historical verification.** The time attribute selects the authorization-period material. When the VDR supplies that period's retained RA-authenticated parameters, the verifier applies the same acceptance equations and time-specific encodings. Parameter authenticity and policy-signature security give authorization verification under the retained material. Availability and retention of those records are system assumptions.

## 7. A concrete retained-session relation

The supplementary experiment records include an internal comparison explaining the role of complete refresh. Consider a diagnostic variant applying only (6) and the two signature-equation scalings. It leaves the commitment $\boldsymbol d_{X_1}$ and the authorization proofs unchanged. For a recorded response $\eta_{0,i}$ and its resulting presentation,

$$
\boldsymbol d_{X_1}(\eta'_i)=\boldsymbol d_{X_1}(\eta_{0,i}).
\tag{27}
$$

An issuer can therefore test exact equality of these public commitment bytes against its saved responses. This relation is deterministic for that particular variant even though signature verification still succeeds. The complete protocol instead applies independent mask increments to this commitment and the complete proof system. Lemma 1 and Theorem 1 establish its privacy; the diagnostic equality check illustrates (27). Timing the actual refresh call reports the cost of that protection within the existing signature format.

## References

[1] Charanjit S. Jutla and Arnab Roy. *Improved Structure Preserving Signatures under Standard Bilinear Assumptions*. [Paper](https://eprint.iacr.org/2017/025.pdf), §2.2, Figure 2 and the SPS security analysis. The certificate uses the exchanged source-group orientation.

[2] Georg Fuchsbauer, Christian Hanser, and Daniel Slamanig. *Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials*. [Paper](https://eprint.iacr.org/2014/944.pdf), Scheme 1, Theorem 2 and the signature-adaptation lemma.

[3] Alex Escala and Jens Groth. *Fine-Tuning Groth–Sahai Proofs*. [Paper](https://eprint.iacr.org/2013/662.pdf), Figures 1 and 8 and the complete PPE extraction/simulation analysis.

[4] Mihir Bellare and Gregory Neven. *Multi-Signatures in the Plain Public-Key Model and a General Forking Lemma*. [Author manuscript](https://cseweb.ucsd.edu/~mihir/papers/multisignatures.pdf), §3, Lemma 1.

The component references establish their respective primitives. The ABS composition, exact-response normalization, full-refresh distribution argument, source-content experiment, and resulting bounds above are the derivations for this construction.
